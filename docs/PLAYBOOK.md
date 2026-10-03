# Manual trace playbook

How a hit becomes a Vertical Book by hand. Horizontal automates the no-judgment steps
(1–8 partial) and leaves the rest as `gap` nodes. The human does the judgment and raises
links to `confirmed`/`dropped` with a written basis.

| Step | Action | Vertical node / link |
|------|--------|----------------------|
| 1 | Trigger — the hit, with time | `event` |
| 2 | Preserve — the exact raw line(s) with raw_ref | `observation` (source = file+line+sha256) |
| 3 | Identify — `ps -o pid,ppid,lstart,user,comm -p <pid>`; build proc_key | `process` id `proc-<pid>-<YYYYMMDDTHHMMSS>` |
| 4 | Threads — `ps -M <pid>` | `observation` |
| 5 | Parent chain — walk ppid to launchd | `process` + `spawned-by` links (id-match until start times agree) |
| 6 | Binary — `codesign -dvv`, `spctl --assess -vv`, `shasum -a 256` | `observation`; unsigned/ad-hoc → `note` |
| 7 | Network — `lsof -nP -i -a -p <pid>` at capture time | hit→process link becomes `confirmed` only here, basis "direct evidence" |
| 8 | Persistence — LaunchAgents/Daemons, `sudo sfltool dumpbtm` | `observation` / `gap` |
| 9 | Unknowns | `gap` (what would close it) |
| 10 | Verdict — benign/suspicious/malicious, with reason | `note` |
| 11 | Contain (by hand) — order below | `command` |
| 12 | Close — `vertical_verify`, monitoring report | `note` |

## Containment order (evidence first)
1. `kill -STOP <pid>` — suspend, keep memory/state.
2. Block that binary in LuLu or a pf rule (not pull Wi-Fi) where possible.
3. Record hashes, then `kill -9 <pid>`.
4. Move the binary to `~/Quarantine/<case-id>/`, `chmod 000`, keep the original path in the node.
5. Disable its persistence item (move the plist into the same quarantine folder).
6. **Write the undo steps** in the `command` node. A containment without an undo is incomplete.

## Read-only command catalog
`ps -axo pid,ppid,lstart,user,comm` · `ps -M <pid>` · `lsof -nP -i` / `lsof -nP -i -a -p <pid>` ·
`lsof -nP -iTCP -sTCP:LISTEN` · `nettop -L 1 -P` ·
`log show --last 10m --predicate 'processID == <pid>'` · `codesign -dvv <path>` ·
`spctl --assess -vv <path>` · `shasum -a 256 <path>` · `xattr -l <path>` ·
`ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons` · `sudo sfltool dumpbtm` ·
`launchctl print gui/$(id -u)/<label>`
