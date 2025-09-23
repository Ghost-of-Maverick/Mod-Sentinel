#!/usr/bin/env bash
# /temp/run_attack_wrapper.sh <command>
# Wrapper tested by you: starts command under nohup+setsid, writes pidfile with
# the launcher PID and all descendant PIDs (one per linha).

TARGET="$1"
PIDFILE="/tmp/attack.pid"
LOGFILE="/tmp/attack.out"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 /path/to/script-or-cmd" >&2
  exit 2
fi

cd /temp || exit 1

# start the target under setsid so it detaches cleanly; keep shell wrapper minimal
nohup setsid "$TARGET" > "$LOGFILE" 2>&1 &
WRAPPER_PID=$!

# small sleep to allow child processes to appear
sleep 0.05

# collect direct children and grandchildren (recursively)
# pgrep -P returns children; we'll collect recursively using a loop
collect_descendants() {
  local parent=$1
  local all="$parent"
  local children
  children=$(pgrep -P "$parent" 2>/dev/null || true)
  for c in $children; do
    # avoid infinite loops
    if ! echo "$all" | grep -qx "$c"; then
      all="${all} $c"
      all="$(collect_descendants "$c") $all"
    fi
  done
  echo "$all"
}

PIDS="$(collect_descendants $WRAPPER_PID || echo "$WRAPPER_PID")"
# Deduplicate and write one per line, prefer children first then wrapper
# We'll print children (sorted unique) and then wrapper last.
echo "$PIDS" | tr ' ' '\n' | awk '!x[$0]++' > "$PIDFILE"
# ensure wrapper PID also listed if not present
grep -qx "$WRAPPER_PID" "$PIDFILE" || printf '%s\n' "$WRAPPER_PID" >> "$PIDFILE"

# print pidfile so remote caller may see it in stdout (useful for debug)
cat "$PIDFILE" 2>/dev/null || true

# exit: wrapper itself can exit; the actual long-running process(es) remain.
exit 0