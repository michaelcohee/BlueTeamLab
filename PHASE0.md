# Phase 0: macOS preparation

Complete these steps before the five-minute sizing run. Runtime telemetry stays in
`$HOME/VerticalData`, outside this repository.

## 1. Check free space

The collector enforces a 3 GB lab-data cap and a 4 GB free-space floor, so begin with at
least 7 GB free:

```zsh
df -h "$HOME"
```

## 2. Install local dependencies

```zsh
brew install zeek duckdb jq
brew install --cask osquery

zeek --version
duckdb --version
jq --version
osqueryi --version
```

The Blueware command application has one Python dependency:

```zsh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-cli.txt
```

The Streamlit dashboard is optional:

```zsh
.venv/bin/python -m pip install -r requirements-ui.txt
```

## 3. Grant Full Disk Access

In **System Settings → Privacy & Security → Full Disk Access**, enable the terminal app that
will run the collector. Quit and reopen that terminal afterward. `collect/lab.sh start`
performs a short `eslogger` probe and aborts if the required access is unavailable.

## 4. Create the external data directory

```zsh
mkdir -p "$HOME/VerticalData"
chmod 700 "$HOME/VerticalData"
export VERTICALDATA="$HOME/VerticalData"
```

The collector refuses to use a directory located inside a Git working tree.

## 5. Verify the source tree

```zsh
./dl test
./blueware inspect-control --pretty
```

## 6. Size a five-minute capture

```zsh
collect/lab.sh dryrun 5
```

The command starts the same Zeek, osquery, and exec-only eslogger sources used for the real
capture, stops them, compresses their output, and prints per-source sizes plus a simple
24-hour projection. Review the projection before starting a longer run.

## 7. Run the bounded 24-hour capture

```zsh
collect/lab.sh start --hours 24
collect/lab.sh status
```

The guard stops collectors at the time limit, 3 GB cap, or 4 GB free-space floor. After the
window ends, close and compress the session:

```zsh
collect/lab.sh stop
```

No capture output belongs in Git.
