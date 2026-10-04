"""Local, read-only Streamlit view for detection-lab telemetry and case drafts."""

from collections import Counter
import html
import os
import shutil

import streamlit as st

from lab import common as C
from lab.dashboard_data import MIB, human_bytes, load_book, load_hits, load_snapshot
from lab.vbook import VBookError

st.set_page_config(page_title="Detection Lab · Observatory", layout="wide",
                   initial_sidebar_state="expanded")

st.markdown("""
<style>
  :root {--ink:#f2efe5; --muted:#9eb5b9; --teal:#58d4c6; --line:#2a4852; --panel:#112b34;}
  header[data-testid="stHeader"] {background:transparent;}
  [data-testid="stToolbar"], [data-testid="stDecoration"] {display:none;}
  .block-container {max-width:1320px; padding-top:1.35rem; padding-bottom:3.5rem;}
  [data-testid="stSidebar"] {border-right:1px solid #27444d; background:#0d2830;}
  [data-testid="stSidebar"] .block-container {padding-top:2.2rem;}
  .eyebrow {font-size:.7rem; letter-spacing:.2em; text-transform:uppercase; color:#78d7ce; font-weight:750;}
  .hero {padding:1.55rem 1.8rem; border:1px solid #2b4a54; border-radius:14px;
         background:#112d36; margin-bottom:.9rem;}
  .hero-grid {display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:center; gap:2rem;}
  .hero h1 {font-size:2.15rem; line-height:1.08; margin:.45rem 0 .55rem; color:var(--ink);}
  .hero p {color:#aec2c5; margin:0; max-width:760px;}
  .hero-side {display:flex; align-items:center; gap:1.3rem; min-width:280px;}
  .hero-stat {padding-left:1.3rem; border-left:1px solid #31515b; color:#a7bdc1; font-size:.77rem;}
  .hero-stat strong {display:block; color:var(--ink); font-size:.92rem; margin-bottom:.2rem;}
  .section-heading {font-size:1.05rem; color:#efe9da; letter-spacing:.02em; margin:.9rem 0 .45rem;}
  .status {display:inline-block; border-radius:99px; padding:.3rem .75rem; font-size:.75rem;
           font-weight:700; letter-spacing:.06em; text-transform:uppercase;}
  .status.ok {background:#17473f; color:#9de5cc;}
  .status.warn {background:#513c21; color:#f5cd8a;}
  .status.idle {background:#283f48; color:#c6d6d8;}
  .small-note {color:#93aab0; font-size:.82rem;}
  .mission-kicker {font-size:.68rem; letter-spacing:.2em; text-transform:uppercase; color:#75d9cf;
                   font-weight:750; margin-bottom:.35rem;}
  .mission-title {font-size:2rem; line-height:1.1; color:var(--ink); font-weight:760; margin:0 0 .4rem;}
  .mission-copy {color:#afc2c5; font-size:.98rem; max-width:790px; margin-bottom:.35rem;}
  .readiness {display:grid; grid-template-columns:1.2fr 2fr auto; gap:1rem; align-items:center;
              padding:.85rem 0; border-top:1px solid #294751;}
  .readiness strong {color:#edf0e9;}
  .readiness span {color:#9eb4b8; font-size:.86rem;}
  .ready {color:#72e1c8 !important; font-size:.7rem !important; letter-spacing:.12em; font-weight:750;}
  .next {color:#88ccff !important; font-size:.7rem !important; letter-spacing:.12em; font-weight:750;}
  .journey {display:grid; grid-template-columns:repeat(5,1fr); border-top:1px solid #41606a; margin-top:1rem;}
  .journey-step {padding:.8rem .9rem 0 0; color:#829ca2; min-height:92px;}
  .journey-step + .journey-step {padding-left:1rem; border-left:1px solid #27434c;}
  .journey-step b {display:block; color:#a8bdc1; margin:.25rem 0;}
  .journey-step.active {color:#aedbd6; border-top:3px solid var(--teal); margin-top:-2px;}
  .journey-step.active b {color:var(--ink);}
  .journey-step small {font-size:.76rem; line-height:1.4;}
  div[data-testid="stVerticalBlockBorderWrapper"] {border-color:#2c4d57; background:#112a33; border-radius:14px;}
  [data-testid="stCode"] {border:1px solid #345763; border-radius:9px;}
  div[data-testid="stMetric"] {border:1px solid #2b434d; background:#172b34; padding:1rem 1.15rem;
                                  border-radius:14px; min-height:112px;}
  div[data-testid="stMetricLabel"] {color:#a9c1c3;}
  div[data-testid="stMetricValue"] {color:#f4f0e6;}
  @media (max-width:900px) {
    .hero-grid {grid-template-columns:1fr; gap:1rem;}
    .hero-side {justify-content:space-between; min-width:0;}
    .journey {grid-template-columns:1fr; border-top:0;}
    .journey-step, .journey-step + .journey-step {border-left:0; border-top:1px solid #294751; padding:.7rem 0; min-height:0;}
    .readiness {grid-template-columns:1fr auto;}
    .readiness span:nth-child(2) {display:none;}
  }
</style>
""", unsafe_allow_html=True)


@st.cache_data(ttl=15, show_spinner=False)
def snapshot(root):
    return load_snapshot(root)


@st.cache_data(ttl=15, show_spinner=False)
def hits(root, filename):
    return load_hits(root, filename)


with st.sidebar:
    st.markdown('<div class="eyebrow">DETECTION LAB</div>', unsafe_allow_html=True)
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
free_text = human_bytes(data["free_bytes"]) if data["free_bytes"] is not None else "Unavailable"
st.markdown(
    '<div class="hero"><div class="hero-grid"><div><div class="eyebrow">FIELD NOTES / SINGLE HOST</div>'
    '<h1>Detection Lab Observatory</h1>'
    '<p>Capture health, storage headroom, explainable detections, and Horizontal case drafts '
    'in one local view.</p></div><div class="hero-side">'
    '<span class="status %s">%s</span><div class="hero-stat"><strong>%s free</strong>3.0 GiB lab budget</div>'
    '</div></div></div>' % (status_class, status_text, html.escape(free_text)),
    unsafe_allow_html=True,
)


def pipeline_strip(data):
    """Five stages, each done / active (the next thing to do) / pending, from what's on disk."""
    n_sess, n_norm = len(data["sessions"]), data.get("norm_count", 0)
    has_base, n_hits, n_books = bool(data["baseline"]), data.get("hits_count", 0), len(data["books"])
    stages = [
        ("01", "Capture", n_sess, "%d session%s" % (n_sess, "" if n_sess == 1 else "s"), "none yet"),
        ("02", "Normalize", n_norm, "%d normalized" % n_norm, "awaiting capture"),
        ("03", "Baseline", has_base, "built" if has_base else "", "awaiting normalize"),
        ("04", "Hunt", n_hits, "%d hit file%s" % (n_hits, "" if n_hits == 1 else "s"), "awaiting baseline"),
        ("05", "Trace", n_books, "%d auto Book%s" % (n_books, "" if n_books == 1 else "s"), "awaiting hits"),
    ]
    done = [bool(v) for _, _, v, _, _ in stages]
    active_idx = next((i for i, d in enumerate(done) if not d), None)  # first incomplete = next action
    cells = []
    for i, (num, title, val, done_txt, pending_txt) in enumerate(stages):
        cls = "done" if done[i] else ("active" if i == active_idx else "pending")
        sub = done_txt if done[i] else ("next step →" if i == active_idx else pending_txt)
        cells.append('<div class="journey-step %s"><span>%s</span><b>%s</b><small>%s</small></div>'
                     % (cls, num, title, html.escape(str(sub))))
    st.markdown('<div class="journey">' + "".join(cells) + "</div>", unsafe_allow_html=True)


def mission_start(data, root):
    """Read-only first-run guidance shown until the first collection session exists."""
    required = ("zeek", "duckdb", "jq", "osqueryi")
    found = [name for name in required if shutil.which(name)]
    tools_ready = len(found) == len(required)
    directory_ready = data["exists"] and os.access(os.path.expanduser(root), os.R_OK | os.W_OK)
    enough_disk = (data["free_bytes"] is not None and
                   data["free_bytes"] >= data["floor_bytes"] + data["cap_bytes"])
    root_label = html.escape(os.path.expanduser(root))
    tools_label = " · ".join(found) if found else "No required tools found on PATH"
    with st.container(border=True):
        intro, estimate = st.columns([4, 1], gap="large")
        with intro:
            st.markdown('<div class="mission-kicker">MISSION START</div>'
                        '<div class="mission-title">Ready for first capture</div>'
                        '<div class="mission-copy">Check the local environment, then run a five-minute '
                        'sizing capture. The Observatory stays read-only; commands run in Terminal.</div>',
                        unsafe_allow_html=True)
        with estimate:
            st.metric("Estimated time", "5 minutes")
            st.caption("Outcome: per-source sizes and a 24-hour storage projection.")

        st.markdown(
            '<div class="readiness"><strong>1. Tools installed</strong><span>%s</span>'
            '<span class="%s">%s</span></div>'
            '<div class="readiness"><strong>2. Data directory ready</strong><span>%s · %s free</span>'
            '<span class="%s">%s</span></div>'
            '<div class="readiness"><strong>3. Terminal authorization</strong>'
            '<span>Grant temporary sudo access, then run the rehearsal.</span>'
            '<span class="next">YOUR NEXT STEP</span></div>'
            % (html.escape(tools_label), "ready" if tools_ready else "next", "READY" if tools_ready else "CHECK",
               root_label, html.escape(free_text), "ready" if directory_ready and enough_disk else "next",
               "READY" if directory_ready and enough_disk else "CHECK"),
            unsafe_allow_html=True,
        )
        command, note = st.columns([4, 1], gap="large")
        with command:
            st.markdown("**1. Authorize this Terminal session**")
            st.code("sudo -v", language="bash")
        with note:
            st.caption("Prompts for your password locally and keeps sudo available briefly.")
        command, note = st.columns([4, 1], gap="large")
        with command:
            st.markdown("**2. Run the five-minute sizing capture**")
            st.code("collect/lab.sh dryrun 5", language="bash")
        with note:
            st.caption("Collects a small sample and reports byte sizes. It does not start the 24-hour run.")

    st.markdown('<div class="mission-kicker" style="margin-top:1.25rem">YOUR JOURNEY</div>'
                '<div class="small-note">From raw telemetry to explainable case drafts.</div>',
                unsafe_allow_html=True)
    pipeline_strip(data)

tabs = st.tabs(["Overview", "Detections", "Case drafts"])

with tabs[0]:
    if not data["sessions"]:
        mission_start(data, root)
    else:
        pipeline_strip(data)
        free = data["free_bytes"]
        used = data["used_bytes"]
        cap = data["cap_bytes"]
        cols = st.columns(4)
        cols[0].metric("Lab data on disk", human_bytes(used))
        cols[1].metric("Lab budget used", "%.1f%%" % (100 * used / cap) if cap else "—")
        cols[2].metric("Free disk", human_bytes(free) if free is not None else "—")
        cols[3].metric("Sessions", str(len(data["sessions"])))
        st.progress(min(1.0, used / cap) if cap else 0.0,
                    text="Storage budget · %s remaining" % human_bytes(max(0, cap - used)))
        if free is not None and free < data["floor_bytes"]:
            st.error("Free disk is below the configured floor of %s." % human_bytes(data["floor_bytes"]))
        if used >= cap:
            st.error("Lab data has reached or exceeded the configured cap.")

        st.markdown('<div class="section-heading">Collection sessions</div>', unsafe_allow_html=True)
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
