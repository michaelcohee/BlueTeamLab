"""Local, read-only Streamlit view for detection-lab telemetry and case drafts."""

from collections import Counter
import os

import streamlit as st

from lab import common as C
from lab.dashboard_data import MIB, human_bytes, load_book, load_hits, load_snapshot
from lab.vbook import VBookError

st.set_page_config(page_title="Detection Lab · Observatory", page_icon="◈", layout="wide",
                   initial_sidebar_state="expanded")

st.markdown("""
<style>
  .block-container {max-width: 1320px; padding-top: 2rem; padding-bottom: 4rem;}
  [data-testid="stSidebar"] {border-right: 1px solid #273b45;}
  .eyebrow {font-size:.72rem; letter-spacing:.19em; text-transform:uppercase; color:#79c9c3; font-weight:700;}
  .hero {padding:1.8rem 2rem; border:1px solid #2c4850; border-radius:18px;
         background:linear-gradient(120deg,#142d34 0%,#10232c 55%,#183b42 100%); margin-bottom:1.2rem;}
  .hero h1 {font-size:2.25rem; line-height:1.1; margin:.45rem 0 .55rem; color:#f2efe5;}
  .hero p {color:#a9bfc2; margin:0; max-width:760px;}
  .section-heading {font-size:1.05rem; color:#efe9da; letter-spacing:.02em; margin:.9rem 0 .45rem;}
  .status {display:inline-block; border-radius:99px; padding:.3rem .75rem; font-size:.75rem;
           font-weight:700; letter-spacing:.06em; text-transform:uppercase; margin-bottom:.8rem;}
  .status.ok {background:#17473f; color:#9de5cc;}
  .status.warn {background:#513c21; color:#f5cd8a;}
  .status.idle {background:#283b44; color:#adc5ca;}
  .small-note {color:#93aab0; font-size:.82rem;}
  div[data-testid="stMetric"] {border:1px solid #2b434d; background:#172b34; padding:1rem 1.15rem;
                                  border-radius:14px; min-height:112px;}
  div[data-testid="stMetricLabel"] {color:#a9c1c3;}
  div[data-testid="stMetricValue"] {color:#f4f0e6;}
</style>
""", unsafe_allow_html=True)


@st.cache_data(ttl=15, show_spinner=False)
def snapshot(root):
    return load_snapshot(root)


@st.cache_data(ttl=15, show_spinner=False)
def hits(root, filename):
    return load_hits(root, filename)


with st.sidebar:
    st.markdown('<div class="eyebrow">◈ DETECTION LAB</div>', unsafe_allow_html=True)
    st.markdown("### Observatory")
    st.caption("Local telemetry · read-only view")
    st.divider()
    root = st.text_input("Data directory", value=C.data_dir(), help="Local $VERTICALDATA path")
    if st.button("Refresh", width="stretch"):
        st.cache_data.clear()
    st.caption("The dashboard reads files only. Collection and tracing remain CLI steps.")
    st.divider()
    st.markdown("**Runbook**")
    st.code("collect/lab.sh status\n./dl normalize\n./dl baseline --until <UTC>\n./dl hunt", language="bash")
    st.caption("Bind to localhost only; real telemetry stays on this Mac.")

data = snapshot(root)
active = data["active"]
status_text = "CAPTURE ACTIVE" if active else ("NO DATA DIRECTORY" if not data["exists"] else "COLLECTOR IDLE")
status_class = "ok" if active else ("warn" if not data["exists"] else "idle")
st.markdown('<div class="hero"><div class="eyebrow">FIELD NOTES / SINGLE HOST</div>'
            '<h1>Detection Lab Observatory</h1>'
            '<p>Capture health, storage headroom, explainable detections, and Horizontal case drafts '
            'in one local view.</p></div>', unsafe_allow_html=True)
st.markdown('<span class="status %s">%s</span>' % (status_class, status_text), unsafe_allow_html=True)

if not data["exists"]:
    st.info("Create ~/VerticalData and run the Phase 0 setup before opening a session.")

tabs = st.tabs(["Overview", "Detections", "Case drafts"])

with tabs[0]:
    free = data["free_bytes"]
    used = data["used_bytes"]
    cap = data["cap_bytes"]
    cols = st.columns(4)
    cols[0].metric("Lab data on disk", human_bytes(used))
    cols[1].metric("Lab budget used", "%.1f%%" % (100 * used / cap) if cap else "—")
    cols[2].metric("Free disk", human_bytes(free) if free is not None else "—")
    cols[3].metric("Sessions", str(len(data["sessions"])))
    st.progress(min(1.0, used / cap) if cap else 0.0, text="Storage budget · %s remaining" % human_bytes(max(0, cap - used)))
    if free is not None and free < data["floor_bytes"]:
        st.error("Free disk is below the configured floor of %s." % human_bytes(data["floor_bytes"]))
    if used >= cap:
        st.error("Lab data has reached or exceeded the configured cap.")

    st.markdown('<div class="section-heading">Collection sessions</div>', unsafe_allow_html=True)
    if not data["sessions"]:
        st.info("No captures yet. A five-minute dry run will appear here with per-source sizes.")
    else:
        rows = []
        for session in data["sessions"]:
            state = "LIMIT HIT" if session["limit_hit"] else ("RUNNING" if session["active"] else
                    ("STOPPED" if session["stopped"] else "INCOMPLETE"))
            rows.append({"Session": session["name"], "State": state,
                         "Zeek": human_bytes(session["sources"]["Zeek"]),
                         "eslogger": human_bytes(session["sources"]["eslogger"]),
                         "osquery": human_bytes(session["sources"]["osquery"]),
                         "Total": human_bytes(session["bytes"])})
        st.dataframe(rows, hide_index=True, width="stretch")
        chosen = st.selectbox("Inspect session", [s["name"] for s in data["sessions"]])
        session = next(s for s in data["sessions"] if s["name"] == chosen)
        source_rows = [{"Source": name, "MiB on disk": round(size / MIB, 3)}
                       for name, size in session["sources"].items() if size]
        if source_rows:
            st.bar_chart(source_rows, x="Source", y="MiB on disk", horizontal=True)
        with st.expander("Collector diagnostics"):
            st.json(session["meta"])
            for source, lines in session["errors"].items():
                if lines:
                    st.markdown("**%s stderr (last lines)**" % source)
                    st.code("\n".join(lines), language="text")
            if not any(session["errors"].values()):
                st.caption("No stderr lines recorded in the known collector files.")

    left, right = st.columns(2)
    with left:
        st.markdown('<div class="section-heading">Baseline</div>', unsafe_allow_html=True)
        base = data["baseline"]
        if base:
            st.metric("Events in baseline", f"{base.get('events', 0):,}")
            st.caption("%s → %s" % (base.get("from_ts") or "?", base.get("to_ts") or "?"))
            st.caption("Cutoff: %s" % (base.get("until") or "not set"))
        else:
            st.info("No baseline built yet.")
    with right:
        st.markdown('<div class="section-heading">Guard log</div>', unsafe_allow_html=True)
        if data["guard_lines"]:
            st.code("\n".join(data["guard_lines"][-5:]), language="text")
        else:
            st.info("The guard has not written a status line yet.")

with tabs[1]:
    st.markdown('<div class="section-heading">Explainable hunt results</div>', unsafe_allow_html=True)
    latest = data["latest_hits"]
    if not latest:
        st.info("No hits file yet. Run `./dl hunt` after a baseline and a separate hunt window exist.")
    else:
        all_hits, truncated = hits(root, latest)
        st.caption("Latest file: %s · %d loaded%s" % (latest, len(all_hits), " (display limit reached)" if truncated else ""))
        rule_counts = Counter(h.get("rule_id") or "?" for h in all_hits)
        if rule_counts:
            st.bar_chart([{"Rule": rule, "Hits": count} for rule, count in sorted(rule_counts.items())],
                         x="Rule", y="Hits")
        choices = ["All rules"] + sorted(rule_counts)
        selected_rule = st.selectbox("Rule", choices)
        filtered = [h for h in all_hits if selected_rule == "All rules" or h.get("rule_id") == selected_rule]
        if filtered:
            st.dataframe([{"ID": h.get("hit_id"), "Rule": h.get("rule_id"),
                           "First seen": h.get("first_ts"), "Process": h.get("process_path") or "Unattributed",
                           "Summary": h.get("summary") or "", "Raw refs": len(h.get("evidence") or [])}
                          for h in filtered], hide_index=True, width="stretch")
            selected_id = st.selectbox("Inspect hit", [h.get("hit_id") for h in filtered])
            selected_hit = next(h for h in filtered if h.get("hit_id") == selected_id)
            m1, m2, m3 = st.columns(3)
            m1.metric("Rule", selected_hit.get("rule_id") or "—")
            m2.metric("Attribution", selected_hit.get("attribution") or "none")
            m3.metric("Raw references", str(len(selected_hit.get("evidence") or [])))
            st.write(selected_hit.get("summary") or "No summary")
            with st.expander("Metrics and evidence references"):
                st.json({"metrics": selected_hit.get("metrics"), "evidence": selected_hit.get("evidence")})
            st.code("./dl trace %s --kind SIMULATION" % selected_id, language="bash")
            st.caption("Choose REAL or SIMULATION based on the case. This dashboard never runs the trace command.")
        else:
            st.success("No hits in this file for the selected rule.")

with tabs[2]:
    st.markdown('<div class="section-heading">Horizontal drafts</div>', unsafe_allow_html=True)
    st.caption("[AUTO] Books are generated leads. Human confirmation and verdicts belong in Vertical.")
    if not data["books"]:
        st.info("No auto Books yet. Trace a hit from the CLI to create one.")
    else:
        book_name = st.selectbox("Book", data["books"])
        try:
            book = load_book(root, book_name)
        except (OSError, VBookError, UnicodeError) as exc:
            st.error("Could not open Book: %s" % exc)
        else:
            st.subheader(book.title)
            c1, c2, c3 = st.columns(3)
            c1.metric("Book kind", book.kind)
            c2.metric("Nodes", str(len(book.nodes)))
            c3.metric("Gaps", str(sum(n["kind"] == "gap" for n in book.nodes)))
            st.dataframe([{"Kind": n["kind"], "Title": n["title"], "Source": n["source"]}
                          for n in book.nodes], hide_index=True, width="stretch")
            with st.expander("Links and status"):
                st.dataframe([{"From": link["from"], "To": link["to"],
                               "Relationship": link["relationship"], "Status": link["status"]}
                              for link in book.links], hide_index=True, width="stretch")
            with st.expander("Read node text"):
                node_ids = [n["id"] for n in book.nodes]
                if node_ids:
                    node_id = st.selectbox("Node", node_ids)
                    node = next(n for n in book.nodes if n["id"] == node_id)
                    st.text(node["text"])

st.markdown('<p class="small-note">DETECTION LAB · LOCAL ONLY · READ-ONLY OBSERVATORY</p>', unsafe_allow_html=True)
