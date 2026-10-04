<#
.SYNOPSIS
  idtscan-windows - read-only IDT integrity scanner for Windows x64.   ** UNTESTED BUILD **

.DESCRIPTION
  Windows has no supported way to read the IDT from user mode, and writing a driver means
  test-signing. So this script drives the Microsoft kernel debugger (kd.exe) READ-ONLY:

    Mode A (recommended)  -DumpPath  a LIVE kernel memory dump. No reboot, no debug mode.
        Make one with Task Manager (Details -> right-click "System" -> Create live kernel
        memory dump file -> Full live kernel memory dump) or Sysinternals:
            livekd64.exe -ml -o C:\dumps\live.dmp
    -Local is not supported for the full scan: local kernel debugging cannot display
    the register state needed for the CR0/GDT checks.

  Against a dump it runs "!idt -a", "lm" and "r cr0", then:
    - resolves each vector's handler to a loaded module
    - flags handlers outside every module (critical), exception/system vectors (0x00-0x2F)
      that don't resolve to nt or hal (high), and CR0.WP = 0 (critical)
    - lists the reserved vectors (0x09, 0x0F, 0x14-0x1F) so you can SEE what Windows put there
  Host checks (no kd needed): VBS/HVCI status, vulnerable-driver blocklist, known-vulnerable
  drivers loaded (WinRing0, RTCore64, ...), and crash history for 0x109 / 0x18C.

  It never writes kernel memory. Output: JSONL (same row shape as idtscan_linux.py).

.EXAMPLE
  .\IdtScan.ps1 -DumpPath C:\dumps\live.dmp -OutFile C:\dumps\idtscan.jsonl
.EXAMPLE
  .\IdtScan.ps1 -HostOnly -OutFile .\host.jsonl      # skip kd, just the host checks
#>
[CmdletBinding()]
param(
    [string]$DumpPath,
    [switch]$Local,
    [switch]$HostOnly,
    [string]$KdPath,
    [string]$SymbolPath = "C:\symbols",
    [string]$OutFile,
    [string]$SaveKdLog          # keep the raw kd transcript (evidence) at this path
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$Version = "0.1.0-untested"
$Source  = "idtscan-windows"
$ScanId  = ([guid]::NewGuid().ToString("N")).Substring(0, 12)
$HostName = $env:COMPUTERNAME

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "IdtScan.ps1 supports Windows x64 only."
}
if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    throw "IdtScan.ps1 requires an x64 Windows host and an x64 PowerShell process."
}

$VectorNames = @{
    0x00="#DE divide error"; 0x01="#DB debug"; 0x02="NMI"; 0x03="#BP breakpoint"; 0x04="#OF overflow";
    0x05="#BR bound range"; 0x06="#UD invalid opcode"; 0x07="#NM device not available"; 0x08="#DF double fault";
    0x09="reserved (was coprocessor segment overrun)"; 0x0A="#TS invalid TSS"; 0x0B="#NP segment not present";
    0x0C="#SS stack fault"; 0x0D="#GP general protection"; 0x0E="#PF page fault"; 0x0F="reserved";
    0x10="#MF x87 FPU error"; 0x11="#AC alignment check"; 0x12="#MC machine check"; 0x13="#XM SIMD floating point";
    0x14="#VE virtualization exception"; 0x15="#CP control protection (CET)"; 0x16="reserved"; 0x17="reserved";
    0x18="reserved"; 0x19="reserved"; 0x1A="reserved"; 0x1B="reserved"; 0x1C="#HV hypervisor injection (AMD)";
    0x1D="#VC VMM communication (AMD)"; 0x1E="#SX security exception (AMD)"; 0x1F="reserved by Intel (Windows: APC_LEVEL software interrupt?)"
}
$Reserved = @(0x09, 0x0F, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F)
# Drivers known to hand ring-0 port I/O / MSR / physical memory access to user mode (BYOVD).
# Short list for the lab; the full list is https://www.loldrivers.io
$KnownVulnDrivers = @("WinRing0", "WinRing0x64", "RTCore64", "gdrv", "AsIO", "AsIO2", "AsIO3",
                      "dbutil_2_3", "iqvw64e", "EneIo64", "GLCKIO2", "kprocesshacker", "mhyprot2", "zamguard64")

function Now { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ") }

$Rows = New-Object System.Collections.Generic.List[string]
function Emit([string]$EventType, [hashtable]$Fields) {
    $o = [ordered]@{ ts = (Now); capture_ts = (Now); host = $HostName; source = $Source;
                     scan_id = $ScanId; scanner_version = $Version; event_type = $EventType }
    foreach ($k in $Fields.Keys) { $o[$k] = $Fields[$k] }
    $Rows.Add(($o | ConvertTo-Json -Compress -Depth 5))
}
function Say([string]$m) { Write-Host $m }

# ------------------------------------------------------------------ host checks (no kd)

function Get-HostChecks {
    $ctx = @{ os = $null; build = $null; vbs_running = $null; hvci_running = $null;
              vuln_blocklist_enabled = $null; arch = $env:PROCESSOR_ARCHITECTURE }
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $ctx.os = $os.Caption; $ctx.build = $os.BuildNumber
    } catch {}
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
        $ctx.vbs_running  = ($dg.VirtualizationBasedSecurityStatus -eq 2)
        $ctx.hvci_running = (@($dg.SecurityServicesRunning) -contains 2)
    } catch { $ctx.vbs_running = "unknown: $($_.Exception.Message)" }
    try {
        $v = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" -Name VulnerableDriverBlocklistEnable -ErrorAction Stop
        $ctx.vuln_blocklist_enabled = ($v.VulnerableDriverBlocklistEnable -eq 1)
    } catch { $ctx.vuln_blocklist_enabled = "not set (Windows 11 22H2+ defaults to on)" }
    Emit "host_context" $ctx
    if ($ctx.hvci_running -eq $false) {
        Emit "host_finding" @{ finding = "hvci_off"; severity = "medium"; attack = "T1014";
            summary = "Memory integrity (HVCI) is not running; this is host context, not evidence of IDT tampering or HyperGuard state" }
    }

    # Loaded drivers matching the BYOVD short list
    try {
        $drv = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq "Running" }
        foreach ($d in $drv) {
            $base = [IO.Path]::GetFileNameWithoutExtension([string]$d.PathName)
            foreach ($k in $KnownVulnDrivers) {
                if ($d.Name -like "$k*" -or $base -like "$k*") {
                    Emit "host_finding" @{ finding = "vulnerable_driver_loaded"; severity = "high"; attack = "T1068";
                        driver = $d.Name; path = [string]$d.PathName;
                        summary = "Known-vulnerable driver $($d.Name) is running (exposes ring-0 port I/O / MSR / memory to user mode)" }
                }
            }
        }
    } catch {}

    # Crash history: 0x109 CRITICAL_STRUCTURE_CORRUPTION (PatchGuard), 0x18C HYPERGUARD_VIOLATION
    $codes = @{ 265 = "0x109 CRITICAL_STRUCTURE_CORRUPTION"; 396 = "0x18C HYPERGUARD_VIOLATION" }
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Microsoft-Windows-Kernel-Power"; Id = 41 } -ErrorAction Stop
        foreach ($e in $ev) {
            $bc = [int64]$e.Properties[0].Value
            if ($codes.ContainsKey([int]$bc)) {
                Emit "host_finding" @{ finding = "kernel_tamper_bugcheck"; severity = "high"; attack = "T1014";
                    event_time = $e.TimeCreated.ToUniversalTime().ToString("o"); bugcheck = $codes[[int]$bc];
                    summary = "System crashed with $($codes[[int]$bc]); investigate the cause of reported kernel corruption" }
            }
        }
    } catch {}
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = "System"; Id = 1001 } -ErrorAction Stop |
              Where-Object { $_.Message -match "0x00000109|0x0000018c" }
        foreach ($e in $ev) {
            Emit "host_finding" @{ finding = "kernel_tamper_bugcheck"; severity = "high"; attack = "T1014";
                event_time = $e.TimeCreated.ToUniversalTime().ToString("o");
                summary = ($e.Message -split "`n")[0].Trim() }
        }
    } catch {}
}

# ------------------------------------------------------------------ kd

function Find-Kd {
    if ($KdPath) { return $KdPath }
    $c = @("${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\kd.exe",
           "$env:ProgramFiles\Windows Kits\10\Debuggers\x64\kd.exe")
    foreach ($p in $c) { if (Test-Path $p) { return $p } }
    $g = Get-Command kd.exe -ErrorAction SilentlyContinue
    if ($g) { return $g.Source }
    return $null
}

function Invoke-Kd([string]$Kd, [string]$Commands) {
    $kdArgs = @()
    if ($Local) { $kdArgs += "-kl" } else { $kdArgs += @("-z", $DumpPath) }
    $kdArgs += @("-y", $SymbolPath, "-c", "$Commands; q")
    $out = & $Kd @kdArgs 2>&1 | ForEach-Object { [string]$_ }
    return ,$out
}

function ConvertFrom-KdHex([string]$s) {
    $h = ($s -replace '`', '') -replace '^0x', ''
    return [UInt64]::Parse($h, [Globalization.NumberStyles]::HexNumber)
}

function Parse-Lm([string[]]$Lines) {
    # "fffff801`23400000 fffff801`24446000   nt         (pdb symbols)   c:\..."
    $mods = @()
    foreach ($l in $Lines) {
        if ($l -match '^\s*([0-9a-f]{8}`?[0-9a-f]{8})\s+([0-9a-f]{8}`?[0-9a-f]{8})\s+(\S+)') {
            $mods += [pscustomobject]@{ Name = $Matches[3]; Start = (ConvertFrom-KdHex $Matches[1]); End = (ConvertFrom-KdHex $Matches[2]) }
        }
    }
    return $mods
}

function Parse-Idt([string[]]$Lines) {
    # Marker lines "=== CPU n ===" are echoed by .echo; entries look like
    #    0e:	fffff80123456780 nt!KiPageFault
    #    50:	fffff801`2345a000 i8042prt!I8042KeyboardInterruptService (KINTERRUPT ffffd...)
    $cpu = 0; $entries = @()
    foreach ($l in $Lines) {
        if ($l -match '^=== CPU (\d+) ===') { $cpu = [int]$Matches[1]; continue }
        if ($l -match '^\s*([0-9a-f]{2}):\s+([0-9a-f`]{8,17})\s*(.*)$') {
            $entries += [pscustomobject]@{ Cpu = $cpu; Vector = [Convert]::ToInt32($Matches[1], 16);
                Handler = (ConvertFrom-KdHex $Matches[2]); Text = $Matches[3].Trim() }
        }
    }
    return $entries
}

function Resolve-Module($Mods, [UInt64]$Addr) {
    foreach ($m in $Mods) { if ($Addr -ge $m.Start -and $Addr -lt $m.End) { return $m.Name } }
    return $null
}

function Scan-Idt {
    if ($Local) {
        Emit "scan_gap" @{ gap = "local_debugger_unsupported"; detail = "Local kernel debugging cannot display register state required for CR0/GDT checks. Use -DumpPath with a kernel dump." }
        return
    }
    $kd = Find-Kd
    if (-not $kd) {
        Emit "scan_gap" @{ gap = "kd_missing"; detail = "kd.exe not found. Install 'Debugging Tools for Windows' from the Windows SDK or pass -KdPath." }
        return
    }
    if (-not $Local -and -not ($DumpPath -and (Test-Path $DumpPath))) {
        Emit "scan_gap" @{ gap = "no_target"; detail = "Pass -DumpPath <live kernel dump>" }
        return
    }
    Say "kd: $kd"
    $first = Invoke-Kd $kd "vertarget"
    $ncpu = $null
    foreach ($l in $first) { if ($l -match 'MP \((\d+) procs\)') { $ncpu = [int]$Matches[1] } }
    if (-not $ncpu) {
        if ($SaveKdLog) { $first | Set-Content -Encoding UTF8 $SaveKdLog }
        Emit "scan_gap" @{ gap = "cpu_count_unknown"; detail = "Could not parse processor count from kd vertarget output; inspect -SaveKdLog." }
        return
    }
    $cmd = ".reload; .echo === LM ===; lm"
    for ($i = 0; $i -lt $ncpu; $i++) {
        $cmd += "; ~${i}s; .echo === CPU $i ===; r cr0; r gdtr; r gdtl; r idtr; r idtl; dt nt!_KPCR @`$pcr GdtBase IdtBase; .echo === DG ===; dg 0 70; .echo === IDT ===; !idt -a"
    }
    $log = Invoke-Kd $kd $cmd
    if ($SaveKdLog) { $first + $log | Set-Content -Encoding UTF8 $SaveKdLog }

    $mods = @(Parse-Lm $log)
    $entries = @(Parse-Idt $log)
    if ($mods.Count -eq 0) {
        Emit "scan_gap" @{ gap = "module_parse_failed"; detail = "kd ran but no loaded-module ranges were parsed. Handler locations cannot be evaluated. Inspect -SaveKdLog." }
        return
    }
    if ($entries.Count -eq 0) {
        Emit "scan_gap" @{ gap = "idt_parse_failed"; detail = "kd ran but no '!idt' lines parsed. Re-run with -SaveKdLog and check the transcript." }
        return
    }
    $duplicates = @($entries | Group-Object -Property Cpu, Vector | Where-Object { $_.Count -gt 1 })
    if ($duplicates.Count -gt 0) {
        Emit "scan_gap" @{ gap = "idt_cpu_attribution_unverified"; detail = "Duplicate CPU/vector rows were parsed. '!idt -a' can include all processors; inspect -SaveKdLog before treating per-CPU results as valid." }
        return
    }
    $scannedCpus = @($entries | Select-Object -ExpandProperty Cpu | Sort-Object -Unique)
    if ($scannedCpus.Count -ne $ncpu) {
        Emit "scan_gap" @{ gap = "idt_cpu_coverage_incomplete"; detail = "Parsed IDT rows for $($scannedCpus.Count) of $ncpu processors; inspect -SaveKdLog." }
        return
    }

    # CR0 per CPU: "cr0=0000000080050033"
    $cpu = 0
    $cr0Seen = @{}
    foreach ($l in $log) {
        if ($l -match '^=== CPU (\d+) ===') { $cpu = [int]$Matches[1] }
        if ($l -match 'cr0=([0-9a-f]+)') {
            $cr0Seen[$cpu] = $true
            $cr0 = ConvertFrom-KdHex $Matches[1]
            $wp = [bool]($cr0 -band 0x10000)
            Emit "cr0_state" @{ cpu = $cpu; cr0 = ("0x{0:x}" -f $cr0); wp = $wp }
            if (-not $wp) {
                Emit "idt_finding" @{ finding = "cr0_wp_clear"; severity = "critical"; attack = "T1014"; cpu = $cpu;
                    summary = "CR0.WP is 0 on CPU $cpu - the kernel can write read-only pages (classic hook-installation trick)" }
            }
        }
    }
    if ($cr0Seen.Count -ne $ncpu) {
        Emit "scan_gap" @{ gap = "cr0_cpu_coverage_incomplete"; detail = "Parsed CR0 for $($cr0Seen.Count) of $ncpu processors; WP coverage is incomplete." }
    }

    $nfind = 0
    foreach ($e in $entries) {
        $mod = Resolve-Module $mods $e.Handler
        $sym = ($e.Text -replace '\s*\(KINTERRUPT.*$', '').Trim()
        $isIsr = $e.Text -match 'KINTERRUPT'
        $loc = if ($mod) { "module" } else { "unknown" }
        Emit "idt_entry" @{ cpu = $e.Cpu; vector = $e.Vector; vector_hex = ("0x{0:x2}" -f $e.Vector);
            vector_name = $(if ($VectorNames.ContainsKey($e.Vector)) { $VectorNames[$e.Vector] } else { "os-defined" });
            reserved = ($Reserved -contains $e.Vector); handler = ("0x{0:x16}" -f $e.Handler);
            symbol = $sym; module = $mod; location = $loc; device_isr = $isIsr; present = $true }

        if (-not $mod) {
            $nfind++
            Emit "idt_finding" @{ finding = "handler_outside_kernel"; severity = "critical"; attack = "T1014";
                cpu = $e.Cpu; vector = $e.Vector; vector_hex = ("0x{0:x2}" -f $e.Vector); symbol = $sym;
                summary = ("vector 0x{0:x2} on CPU {1} points at 0x{2:x} - not inside any loaded module" -f $e.Vector, $e.Cpu, $e.Handler) }
        } elseif ($e.Vector -lt 0x30 -and $mod -notin @("nt", "hal") -and -not $isIsr) {
            $nfind++
            Emit "idt_finding" @{ finding = "system_vector_not_nt"; severity = "high"; attack = "T1014";
                cpu = $e.Cpu; vector = $e.Vector; vector_hex = ("0x{0:x2}" -f $e.Vector); symbol = $sym; module = $mod;
                summary = ("vector 0x{0:x2} on CPU {1} is handled by {2}, not nt/hal" -f $e.Vector, $e.Cpu, $mod) }
        }
    }
    # A vector present on one CPU but missing or different on another is worth a look.
    $byVec = $entries | Group-Object Vector
    foreach ($g in $byVec) {
        $syms = $g.Group | ForEach-Object { ($_.Text -replace '\+0x[0-9a-f]+', '' -replace '\s*\(KINTERRUPT.*$', '').Trim() } | Sort-Object -Unique
        $mods2 = $g.Group | ForEach-Object { Resolve-Module $mods $_.Handler } | Sort-Object -Unique
        if (@($mods2).Count -gt 1) {
            $nfind++
            Emit "idt_finding" @{ finding = "cpu_mismatch"; severity = "medium"; attack = "T1014"; vector = [int]$g.Name;
                vector_hex = ("0x{0:x2}" -f [int]$g.Name); modules = @($mods2);
                summary = ("vector 0x{0:x2} resolves to different modules on different CPUs: {1}" -f [int]$g.Name, (@($mods2) -join ", ")) }
        }
    }
    Emit "idt_summary" @{ cpus = $ncpu; entries = $entries.Count; modules_loaded = @($mods).Count; findings = $nfind }

    Say ""
    Say "Reserved / exception vectors (CPU 0):"
    foreach ($e in ($entries | Where-Object { $_.Cpu -eq 0 -and $_.Vector -lt 0x30 } | Sort-Object Vector)) {
        $n = if ($VectorNames.ContainsKey($e.Vector)) { $VectorNames[$e.Vector] } else { "" }
        Say ("  0x{0:x2}  {1,-44} {2}" -f $e.Vector, $n, $e.Text)
    }
}

# ------------------------------------------------------------------ main

Get-HostChecks
if (-not $HostOnly) { Scan-Idt }

if ($OutFile) { $Rows | Add-Content -Encoding UTF8 $OutFile; Say "`nWrote $($Rows.Count) rows to $OutFile" }
else { $Rows }

$bad = $Rows | Where-Object { $_ -match '"severity":"(high|critical)"' }
foreach ($b in $bad) { $o = $b | ConvertFrom-Json; Write-Warning ("[{0}] {1}" -f $o.severity.ToUpper(), $o.summary) }
$gaps = $Rows | Where-Object { $_ -match '"event_type":"scan_gap"' }
if ($bad) { exit 3 } elseif ($gaps) { exit 1 } else { exit 0 }
