# idtscan — IDT/GDT integrity scanners (detection-lab add-on)

Experimental read-only checks for x86-64 **IDT** and **GDT** anomalies. A planted gate
(a reserved IDT vector pointing at attacker code, a call gate in the GDT, or CR0.WP
cleared) can be a ring-0 rootkit entry point. Findings are candidates for investigation,
not proof of a hook. The scanners do not write kernel memory.

Output is standalone JSONL. The current `dl normalize` and `dl hunt` commands do not ingest
these event types; integration with Vertical cases remains to be built.

## Platform support

| Platform | Current state |
| --- | --- |
| x86-64 Linux | Scanner implemented; requires readable kernel symbols and `/proc/kcore`. Not yet validated on a live Linux host. |
| Windows x64 | Experimental debugger-output parser; host-only checks do not need a dump. Neither mode has been run on Windows yet. |
| macOS (Apple silicon) | No IDT/GDT: arm64 uses an exception-vector base instead. This scanner has no macOS kernel-memory backend. |
| macOS (Intel) | CPU has IDT/GDT, but the Linux `/proc` route and Windows `kd.exe` route do not apply. No macOS backend exists. |

Do not disable SIP or install a kernel extension to make an IDT scan run on macOS.

## Safe vector 0x1f lab probe

`probe_1f.py` is a standalone, cross-platform analyzer for scanner JSONL. It does not
invoke the vector or perform privileged operations. It flags a user-callable gate, a
handler outside known kernel code, a non-core module handler, duplicate rows, and semantic
changes from a supplied known-good baseline. Raw addresses are ignored during baseline
comparison because KASLR can change them between boots.

```sh
python3 idtscan/probe_1f.py scan.jsonl --pretty
python3 idtscan/probe_1f.py current.jsonl --baseline known-good.jsonl --pretty
```

For an entirely user-space detection exercise, `simulate_1f_events.py` emits harmless
synthetic JSONL. See [SAFE_INSPECTION.md](SAFE_INSPECTION.md) for the lab procedure.

## linux/idtscan_linux.py  (x86-64 Linux implementation; live validation pending)

```
sudo python3 idtscan/linux/idtscan_linux.py --out /secure/path/scan.jsonl
```
- Reads `idt_table` (256 gates) and each CPU's GDT from `/proc/kcore` via `/proc/kallsyms`.
- Flags: IDT handler outside kernel text / inside a module; wrong code segment; a ring-3
  (DPL 3) gate other than 0x03/0x04/0x80; GDT call gates, extra ring-0 code segments,
  conforming code segments, TSS/LDT in the wrong slot, any unexpected present slot.
- Reads the kernel log for the CR0/CR4 pinning tripwires ("CR0 WP bit went missing").
- Reports lockdown, kptr_restrict, taint flags, SMEP/SMAP/UMIP/CET as context.
- Exit 3 = a high/critical finding, 1 = a gap (something couldn't be read), 0 = clean.

**Limits:** needs kernel symbols and a readable `/proc/kcore`
(`lockdown=confidentiality` blocks it — reported as a gap, not a pass). It reads the real
`idt_table`; a rootkit that re-points **IDTR** at a *different* table is not caught by this
read. Output contains kernel addresses; keep the JSONL outside shared repositories.

## windows/IdtScan.ps1  (Windows x64 — BUILT, NOT TESTED)

```powershell
.\IdtScan.ps1 -DumpPath C:\dumps\live.dmp -SaveKdLog kd.txt -OutFile scan.jsonl
.\IdtScan.ps1 -HostOnly -OutFile host.jsonl     # host checks only, no kd
```
Drives `kd.exe` read-only against a **live kernel dump** (no reboot: Task Manager -> Details
-> right-click System -> Create live kernel memory dump). It uses a local symbol cache at
`C:\symbols` by default. `-Local` reports a scan gap because local debugging cannot display
the register state this scanner requests. The dump-mode parser still needs validation
against real debugger output. Intended checks:
- IDT handler outside all modules (critical), a system vector (<0x30) not served by
  nt/hal (high), per-CPU mismatch (medium); duplicate CPU/vector rows produce a scan gap;
- CR0.WP per CPU;
- **PatchGuard / HyperGuard watch:** System-log crash history for **0x109** and **0x18C**;
- VBS/HVCI running state and the vulnerable-driver blocklist setting;
- known-vulnerable (BYOVD) drivers loaded — WinRing0, RTCore64, dbutil_2_3, mhyprot2, …;
- lists what's actually in the reserved vectors (0x0F, 0x1F, …) so you can see them.

**Still TODO (not built):** the GDT parsing on the Windows side — the script already runs
`r gdtr`, the KPCR bases and `dg 0 70`, so with `-SaveKdLog` the raw data is in the
transcript; the code to read it isn't written yet. No tests; parsing needs validation
against a real `kd.txt`. Treat exit 0 as a parser result, not as a certified clean scan.

## Why reserved IDT vectors matter (quick reference)
Reserved x86 vectors can be absent or handled by an OS stub, depending on kernel and CPU.
Code already running in ring 0 could redirect one to a hidden entry point. A present gate
alone is therefore not suspicious; compare its handler, descriptor, and CPU coverage with
the expected layout for that exact system before calling it a hook.
