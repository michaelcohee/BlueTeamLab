#!/usr/bin/env python3
"""idtscan_linux — read-only IDT integrity scanner for x86-64 Linux.

What it does (all READ-ONLY; it never writes kernel memory):
  1. Finds `idt_table` in /proc/kallsyms and reads its 256 gate descriptors from /proc/kcore.
  2. Decodes each gate (handler address, segment, IST, type, DPL, present bit).
  3. Resolves every handler: core kernel text, a loadable module, or UNKNOWN memory.
  4. Flags: handler outside kernel text, handler in a module, wrong code segment,
     user-callable (DPL 3) gates other than the ones Linux sets on purpose.
  5. Checks the kernel log for CR0.WP / CR4 pinning warnings (the kernel's own tripwire
     for code that clears CR0.WP to write read-only memory), plus lockdown/taint context.

Output: one JSON object per line (stdout or --out). A short human summary goes to stderr.
Standard library only, Python 3.6+. Must run as root. Needs /proc/kcore (blocked when the
kernel is in lockdown=confidentiality; the scanner reports that as a gap, not a pass).

Note: Linux maps a read-only alias of idt_table into the CPU entry area and loads IDTR
with that alias. Both map the same physical page, so reading idt_table reads what the
CPU uses. A rootkit that points IDTR at a different table entirely is NOT caught by this
read; see README "Limits".
"""
import argparse
import bisect
import datetime as dt
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import uuid

VERSION = "0.1.0"
SOURCE = "idtscan-linux"
KERNEL_CS = 0x10           # __KERNEL_CS on x86-64
# Gates Linux deliberately makes callable from ring 3 (DPL 3):
#   0x03 #BP (int3), 0x04 #OF (into), 0x80 int 0x80 (32-bit syscall ABI / emulation)
USER_GATES = {0x03, 0x04, 0x80}

# Intel/AMD exception vector names (SDM Vol.3 Table 6-1 + later additions).
VECTOR_NAMES = {
    0x00: "#DE divide error", 0x01: "#DB debug", 0x02: "NMI", 0x03: "#BP breakpoint",
    0x04: "#OF overflow", 0x05: "#BR bound range", 0x06: "#UD invalid opcode",
    0x07: "#NM device not available", 0x08: "#DF double fault",
    0x09: "reserved (was coprocessor segment overrun)", 0x0A: "#TS invalid TSS",
    0x0B: "#NP segment not present", 0x0C: "#SS stack fault", 0x0D: "#GP general protection",
    0x0E: "#PF page fault", 0x0F: "reserved (Linux: P6 spurious-APIC erratum)",
    0x10: "#MF x87 FPU error", 0x11: "#AC alignment check", 0x12: "#MC machine check",
    0x13: "#XM SIMD floating point", 0x14: "#VE virtualization exception",
    0x15: "#CP control protection (CET)", 0x16: "reserved", 0x17: "reserved",
    0x18: "reserved", 0x19: "reserved", 0x1A: "reserved", 0x1B: "reserved",
    0x1C: "#HV hypervisor injection (AMD SEV-SNP)", 0x1D: "#VC VMM communication (AMD SEV-ES)",
    0x1E: "#SX security exception (AMD)", 0x1F: "reserved",
}
RESERVED = {0x09, 0x0F, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1F}
GATE_TYPES = {0xE: "interrupt", 0xF: "trap"}

TAINT_FLAGS = [  # bit -> letter, meaning (Documentation/admin-guide/tainted-kernels.rst)
    (0, "P", "proprietary module loaded"), (1, "F", "module force-loaded"),
    (2, "S", "out-of-spec system"), (3, "R", "module force-unloaded"),
    (4, "M", "machine check"), (5, "B", "bad page"), (6, "U", "user-requested taint"),
    (7, "D", "kernel died (oops/BUG)"), (8, "A", "ACPI table overridden"),
    (9, "W", "kernel warning issued"), (10, "C", "staging driver"),
    (11, "I", "firmware bug workaround"), (12, "O", "out-of-tree module"),
    (13, "E", "unsigned module"), (14, "L", "soft lockup"), (15, "K", "live-patched"),
    (16, "X", "auxiliary"), (17, "T", "struct randomization"), (18, "N", "in-kernel test"),
]

# Kernel's own CR pinning warnings (arch/x86/kernel/cpu/common.c).
KLOG_PATTERNS = [
    ("cr0_wp_missing", re.compile(r"CR0 WP bit went missing"), "high"),
    ("cr4_pinned_changed", re.compile(r"pinned CR4 bits changed"), "high"),
    ("cr0_pinned_changed", re.compile(r"pinned CR0 bits changed"), "high"),
    ("unsigned_module", re.compile(r"module verification failed"), "medium"),
    ("taint_oot", re.compile(r"loading out-of-tree module taints kernel"), "low"),
]


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ------------------------------------------------------------------ symbols / modules

class Symbols:
    """Address -> nearest preceding symbol, from /proc/kallsyms (root sees real addresses)."""

    def __init__(self, path="/proc/kallsyms"):
        self.by_name = {}
        rows = []
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                addr = int(parts[0], 16)
                name = parts[2]
                mod = parts[3].strip("[]") if len(parts) > 3 else None
                if name not in self.by_name and mod is None:
                    self.by_name[name] = addr
                if addr:
                    rows.append((addr, name, mod))
        rows.sort()
        self.addrs = [r[0] for r in rows]
        self.rows = rows
        self.restricted = not rows   # kptr_restrict hides addresses -> all zero

    def get(self, name):
        return self.by_name.get(name)

    def resolve(self, addr):
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i < 0:
            return None, None
        a, name, mod = self.rows[i]
        off = addr - a
        return ("%s+0x%x" % (name, off) if off else name), mod


def read_modules(path="/proc/modules"):
    """[(name, start, end)] for loaded modules. Addresses are 0 unless root."""
    mods = []
    try:
        with open(path) as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 6:
                    start = int(p[5], 16)
                    mods.append((p[0], start, start + int(p[1])))
    except OSError:
        pass
    return mods


# ------------------------------------------------------------------ /proc/kcore

class Kcore:
    """Minimal ELF64 reader for /proc/kcore: maps kernel virtual addresses to file offsets."""

    def __init__(self, path="/proc/kcore"):
        self.fh = open(path, "rb")
        ident = self.fh.read(64)
        if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
            raise ValueError("not a little-endian ELF64 core")
        (e_phoff,) = struct.unpack_from("<Q", ident, 0x20)
        (e_phentsize, e_phnum) = struct.unpack_from("<HH", ident, 0x36)
        self.loads = []
        for i in range(e_phnum):
            self.fh.seek(e_phoff + i * e_phentsize)
            ph = self.fh.read(56)
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from("<IIQQQQ", ph, 0)
            if p_type == 1:  # PT_LOAD
                self.loads.append((p_vaddr, p_offset, p_filesz))

    def read(self, vaddr, size):
        for base, off, filesz in self.loads:
            if base <= vaddr and vaddr + size <= base + filesz:
                self.fh.seek(off + (vaddr - base))
                data = self.fh.read(size)
                if len(data) != size:
                    raise IOError("short read at 0x%x" % vaddr)
                return data
        raise KeyError("0x%x not mapped in kcore" % vaddr)


# ------------------------------------------------------------------ IDT decode

def decode_gate(raw16):
    """x86-64 16-byte gate descriptor -> dict."""
    off_lo, seg, ist_b, attr, off_mid, off_hi, _res = struct.unpack("<HHBBHII", raw16)
    return {
        "handler": off_lo | (off_mid << 16) | (off_hi << 32),
        "segment": seg,
        "ist": ist_b & 0x7,
        "gate_type": attr & 0xF,
        "dpl": (attr >> 5) & 0x3,
        "present": bool(attr & 0x80),
    }


def classify(vector, gate, syms, text_range, modules):
    """Return (location, symbol, module, findings[])."""
    findings = []
    if not gate["present"]:
        return "not-present", None, None, findings
    h = gate["handler"]
    sym, symmod = syms.resolve(h)
    mod = None
    if text_range[0] <= h < text_range[1]:
        loc = "kernel-text"
    else:
        for name, s, e in modules:
            if s <= h < e:
                mod = name
                break
        loc = "module" if mod else "unknown"
    if loc == "module":
        findings.append(("handler_in_module", "high",
                         "vector 0x%02x handler is inside module %s; Linux never puts IDT handlers in modules"
                         % (vector, mod)))
    elif loc == "unknown":
        findings.append(("handler_outside_kernel", "critical",
                         "vector 0x%02x handler 0x%x is outside kernel text and every loaded module"
                         % (vector, h)))
    if gate["segment"] != KERNEL_CS:
        findings.append(("bad_segment", "high",
                         "vector 0x%02x uses code segment 0x%x (expected __KERNEL_CS 0x%x)"
                         % (vector, gate["segment"], KERNEL_CS)))
    if gate["dpl"] == 3 and vector not in USER_GATES:
        findings.append(("user_callable_gate", "high",
                         "vector 0x%02x is callable from ring 3 (DPL 3); only 0x03, 0x04, 0x80 should be"
                         % vector))
    if gate["gate_type"] not in GATE_TYPES:
        findings.append(("bad_gate_type", "high", "vector 0x%02x has gate type 0x%x" % (vector, gate["gate_type"])))
    return loc, sym, mod or symmod, findings


# ------------------------------------------------------------------ GDT decode

# Linux x86-64 GDT layout (arch/x86/include/asm/segment.h). 16 slots of 8 bytes.
GDT_ENTRIES = 16
GDT_EXPECTED = {
    1: "KERNEL32_CS", 2: "KERNEL_CS", 3: "KERNEL_DS", 4: "DEFAULT_USER32_CS",
    5: "DEFAULT_USER_DS", 6: "DEFAULT_USER_CS", 8: "TSS", 10: "LDT",
    12: "TLS", 13: "TLS", 14: "TLS", 15: "CPUNODE",
}
KERNEL_CODE_SLOTS = {1, 2}
SYS_TYPES = {0x2: "LDT", 0x9: "TSS-available", 0xB: "TSS-busy",
             0xC: "CALL-GATE", 0xE: "INTERRUPT-GATE", 0xF: "TRAP-GATE"}


def decode_seg(raw8):
    lo, hi = struct.unpack("<II", raw8)
    access = (hi >> 8) & 0xFF
    flags = (hi >> 20) & 0xF
    return {
        "base": ((lo >> 16) & 0xFFFF) | ((hi & 0xFF) << 16) | (hi & 0xFF000000),
        "limit": (lo & 0xFFFF) | (hi & 0x000F0000),
        "type": access & 0xF, "s": bool(access & 0x10), "dpl": (access >> 5) & 3,
        "present": bool(access & 0x80), "l": bool(flags & 0x2), "db": bool(flags & 0x4),
        "g": bool(flags & 0x8),
    }


def walk_gdt(raw):
    """Yield (index, desc, kind, findings). 64-bit system descriptors take two slots."""
    i = 0
    n = len(raw) // 8
    while i < n:
        d = decode_seg(raw[i * 8:(i + 1) * 8])
        findings = []
        if not d["present"]:
            kind = "null" if i == 0 else "not-present"
            yield i, d, kind, findings
            i += 1
            continue
        if d["s"]:
            code = bool(d["type"] & 0x8)
            kind = "code" if code else "data"
            if code and (d["type"] & 0x4):
                findings.append(("conforming_code_segment", "medium",
                                 "GDT[%d] is a conforming code segment (runs at caller's ring)" % i))
            if code and d["dpl"] == 0 and i not in KERNEL_CODE_SLOTS:
                findings.append(("extra_ring0_code_segment", "high",
                                 "GDT[%d] is a ring-0 code segment; Linux only has them at slots 1 and 2" % i))
            if i not in GDT_EXPECTED:
                findings.append(("unexpected_gdt_slot", "high",
                                 "GDT[%d] is present but Linux leaves that slot empty" % i))
            yield i, d, kind, findings
            i += 1
            continue
        kind = SYS_TYPES.get(d["type"], "system-0x%x" % d["type"])
        if d["type"] in (0xC, 0xE, 0xF):
            hi2 = struct.unpack("<I", raw[i * 8 + 8:i * 8 + 12])[0] if i + 1 < n else 0
            lo, hi = struct.unpack("<II", raw[i * 8:(i + 1) * 8])
            d["target"] = "0x%016x" % ((lo & 0xFFFF) | (hi & 0xFFFF0000) | (hi2 << 32))
            d["target_selector"] = "0x%x" % ((lo >> 16) & 0xFFFF)
            findings.append(("gate_in_gdt", "critical",
                             "GDT[%d] holds a %s (DPL %d -> selector %s, target %s); Linux never uses gates in the GDT"
                             % (i, kind, d["dpl"], d["target_selector"], d["target"])))
        elif kind.startswith("TSS") and i != 8:
            findings.append(("unexpected_tss", "high", "GDT[%d] holds a TSS; Linux's TSS is at slot 8" % i))
        elif kind == "LDT" and i != 10:
            findings.append(("unexpected_ldt", "high", "GDT[%d] holds an LDT descriptor; expected slot 10" % i))
        elif d["type"] not in SYS_TYPES:
            findings.append(("odd_system_descriptor", "medium", "GDT[%d] system type 0x%x" % (i, d["type"])))
        if i not in GDT_EXPECTED:
            findings.append(("unexpected_gdt_slot", "high", "GDT[%d] is present but Linux leaves that slot empty" % i))
        if i + 1 < n:
            hi2 = struct.unpack("<I", raw[i * 8 + 8:i * 8 + 12])[0]
            d["base"] |= hi2 << 32
        yield i, d, kind, findings
        i += 2


def online_cpus(path="/sys/devices/system/cpu/online"):
    txt = read_text(path)
    if not txt:
        return []
    cpus = []
    for part in txt.split(","):
        if "-" in part:
            a, b = part.split("-")
            cpus.extend(range(int(a), int(b) + 1))
        elif part.strip():
            cpus.append(int(part))
    return cpus


# ------------------------------------------------------------------ context checks

def read_text(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def host_context():
    taint_raw = read_text("/proc/sys/kernel/tainted")
    taint = int(taint_raw) if taint_raw and taint_raw.isdigit() else None
    flags = [{"bit": b, "flag": f, "meaning": m} for b, f, m in TAINT_FLAGS if taint and taint & (1 << b)]
    cpu_flags = set()
    info = read_text("/proc/cpuinfo") or ""
    for line in info.splitlines():
        if line.startswith("flags"):
            cpu_flags = set(line.split(":", 1)[1].split())
            break
    lockdown = read_text("/sys/kernel/security/lockdown")
    m = re.search(r"\[(\w+)\]", lockdown or "")
    return {
        "kernel": os.uname().release,
        "machine": os.uname().machine,
        "lockdown": m.group(1) if m else lockdown,
        "kptr_restrict": read_text("/proc/sys/kernel/kptr_restrict"),
        "tainted": taint,
        "taint_flags": flags,
        "cpu_smep": "smep" in cpu_flags, "cpu_smap": "smap" in cpu_flags,
        "cpu_umip": "umip" in cpu_flags, "cpu_cet_ss": "user_shstk" in cpu_flags or "shstk" in cpu_flags,
        "cmdline": read_text("/proc/cmdline"),
    }


def kernel_log_lines():
    """Kernel ring buffer; falls back to journalctl -k. Returns (lines, source)."""
    for cmd in (["dmesg", "--notime"], ["journalctl", "-k", "-b", "--no-pager", "-o", "cat"]):
        try:
            out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=30, check=True).stdout.decode("utf-8", "replace")
            return out.splitlines(), cmd[0]
        except (OSError, subprocess.SubprocessError):
            continue
    return [], None


# ------------------------------------------------------------------ main scan

def scan(kallsyms="/proc/kallsyms", kcore="/proc/kcore", modules_path="/proc/modules",
         klog=None, context=None, cpus_path="/sys/devices/system/cpu/online"):
    """Yield output rows. Paths are parameters so tests can point at synthetic files."""
    scan_id = uuid.uuid4().hex[:12]
    host = socket.gethostname()
    base = {"host": host, "source": SOURCE, "scan_id": scan_id, "scanner_version": VERSION}

    def row(event_type, **kw):
        r = {"ts": now(), "capture_ts": now()}
        r.update(base)
        r["event_type"] = event_type
        r.update(kw)
        return r

    ctx = context if context is not None else host_context()
    yield row("host_context", **ctx)

    if ctx.get("machine") not in (None, "x86_64"):
        yield row("scan_gap", gap="not_x86_64",
                  detail="IDT scanning needs an x86-64 kernel; this is %s" % ctx.get("machine"))
        return

    try:
        syms = Symbols(kallsyms)
    except OSError as e:
        yield row("scan_gap", gap="kallsyms_unreadable", detail=str(e))
        return
    if syms.restricted:
        yield row("scan_gap", gap="kptr_restrict", detail="kallsyms addresses are hidden; run as root")
        return
    idt = syms.get("idt_table")
    stext, etext = syms.get("_stext"), syms.get("_etext")
    if idt is None or stext is None or etext is None:
        yield row("scan_gap", gap="symbol_missing",
                  detail="idt_table/_stext/_etext not in kallsyms (needs CONFIG_KALLSYMS_ALL)")
        return
    modules = read_modules(modules_path)

    kc = None
    try:
        kc = Kcore(kcore)
        raw = kc.read(idt, 256 * 16)
    except (OSError, ValueError, KeyError) as e:
        yield row("scan_gap", gap="kcore_unreadable",
                  detail="%s (lockdown=%s). Not a pass: the IDT/GDT were not checked." % (e, ctx.get("lockdown")))
        raw = None

    if raw is not None:
        counts = {"present": 0, "not_present": 0, "findings": 0}
        for v in range(256):
            g = decode_gate(raw[v * 16:(v + 1) * 16])
            loc, sym, mod, findings = classify(v, g, syms, (stext, etext), modules)
            counts["present" if g["present"] else "not_present"] += 1
            yield row("idt_entry", cpu="all", vector=v, vector_hex="0x%02x" % v,
                      vector_name=VECTOR_NAMES.get(v, "os-defined" if v >= 0x20 else None),
                      reserved=v in RESERVED, handler="0x%016x" % g["handler"] if g["present"] else None,
                      symbol=sym, module=mod, location=loc, segment="0x%x" % g["segment"],
                      ist=g["ist"], dpl=g["dpl"], gate_type=GATE_TYPES.get(g["gate_type"], "0x%x" % g["gate_type"]),
                      present=g["present"])
            for fid, sev, msg in findings:
                counts["findings"] += 1
                yield row("idt_finding", finding=fid, severity=sev, vector=v, vector_hex="0x%02x" % v,
                          symbol=sym, module=mod, summary=msg, attack="T1014")
        yield row("idt_summary", idt_table="0x%016x" % idt, kernel_text="0x%x-0x%x" % (stext, etext),
                  modules_loaded=len(modules), **counts)

    # ---- GDT: one per CPU, at gdt_page + __per_cpu_offset[cpu]
    if raw is not None:
        gdt_sym, pco = syms.get("gdt_page"), syms.get("__per_cpu_offset")
        if gdt_sym is None or pco is None:
            yield row("scan_gap", gap="gdt_symbols_missing", detail="gdt_page / __per_cpu_offset not in kallsyms")
        else:
            nfind = 0
            cpus = online_cpus(cpus_path)
            if not cpus:
                yield row("scan_gap", gap="online_cpus_unreadable",
                          detail="could not determine online CPUs; GDT coverage is unknown")
            for cpu in cpus:
                try:
                    off = struct.unpack("<Q", kc.read(pco + 8 * cpu, 8))[0]
                    gaddr = (gdt_sym + off) & 0xFFFFFFFFFFFFFFFF
                    graw = kc.read(gaddr, GDT_ENTRIES * 8)
                except (KeyError, IOError) as e:
                    yield row("scan_gap", gap="gdt_unreadable", cpu=cpu, detail=str(e))
                    continue
                for idx, d, kind, findings in walk_gdt(graw):
                    if kind == "null":
                        continue
                    yield row("gdt_entry", cpu=cpu, index=idx, selector="0x%x" % (idx * 8),
                              expected=GDT_EXPECTED.get(idx), kind=kind, dpl=d["dpl"], present=d["present"],
                              long_mode=d["l"], base="0x%x" % d["base"], limit="0x%x" % d["limit"],
                              target=d.get("target"), gdt_address="0x%016x" % gaddr)
                    for fid, sev, msg in findings:
                        nfind += 1
                        yield row("gdt_finding", finding=fid, severity=sev, cpu=cpu, index=idx,
                                  summary="CPU %d: %s" % (cpu, msg), attack="T1014")
            yield row("gdt_summary", cpus=len(cpus), findings=nfind,
                      note="GDTR itself is not readable from user space on UMIP CPUs (SGDT is emulated)")

    lines, klsrc = (klog, "provided") if klog is not None else kernel_log_lines()
    if not lines and klsrc is None:
        yield row("scan_gap", gap="kernel_log_unreadable", detail="dmesg and journalctl both failed")
    for n, text in enumerate(lines, 1):
        for fid, rx, sev in KLOG_PATTERNS:
            if rx.search(text):
                yield row("klog_finding", finding=fid, severity=sev, log_source=klsrc, log_line=n,
                          summary=text.strip()[:300], attack="T1014" if fid.startswith("cr") else "T1547.006")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only x86-64 Linux IDT integrity scanner")
    ap.add_argument("--out", help="write JSONL here (default stdout)")
    ap.add_argument("--quiet", action="store_true", help="no summary on stderr")
    a = ap.parse_args(argv)
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "AMD64"):
        print("idtscan_linux: supported only on x86-64 Linux (this is %s/%s)" %
              (sys.platform, platform.machine()), file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("idtscan_linux: must run as root (reads /proc/kcore and real kallsyms addresses)", file=sys.stderr)
        return 2
    out = open(a.out, "a") if a.out else sys.stdout
    worst = 0
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    for r in scan():
        out.write(json.dumps(r, sort_keys=True) + "\n")
        et = r["event_type"]
        if et in ("idt_finding", "gdt_finding", "klog_finding"):
            worst = max(worst, rank.get(r.get("severity"), 0))
        elif et == "scan_gap":
            worst = max(worst, 2)
        if a.quiet:
            continue
        if et in ("idt_finding", "gdt_finding", "klog_finding"):
            print("[%s] %s: %s" % (r["severity"].upper(), r["finding"], r["summary"]), file=sys.stderr)
        elif et == "scan_gap":
            print("[GAP] %s: %s" % (r["gap"], r["detail"]), file=sys.stderr)
        elif et == "idt_entry" and (r["reserved"] or r["vector"] < 0x20):
            print("  %s %-44s %-12s %s" % (r["vector_hex"], r["vector_name"], r["location"],
                                           r["symbol"] or "-"), file=sys.stderr)
        elif et == "idt_summary":
            print("IDT @ %s: %d present, %d not present, %d findings"
                  % (r["idt_table"], r["present"], r["not_present"], r["findings"]), file=sys.stderr)
        elif et == "gdt_summary":
            print("GDT: %d CPUs scanned, %d findings" % (r["cpus"], r["findings"]), file=sys.stderr)
    if a.out:
        out.close()
    return {0: 0, 1: 0, 2: 1}.get(worst, 3)   # exit 3 = high/critical finding


if __name__ == "__main__":
    sys.exit(main())
