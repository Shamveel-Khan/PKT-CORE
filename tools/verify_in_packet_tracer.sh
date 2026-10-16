#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Validate that a repacked container opens in the real Packet Tracer.
#
# The project already proves `encode(decode(f)) == f` byte-for-byte across
# 1,058 real files. This script is the *other* claim from the brief: that the
# application itself accepts what we write. It boots Packet Tracer headless
# under Xvfb, loads a file, and captures the screen so a human (or image diff)
# can confirm the topology rendered.
#
# Usage:
#   tools/verify_in_packet_tracer.sh <pt-binary> <file.pkt> [outfile.png]
#
# Packet Tracer version notes (established empirically):
#   * PT 9.0.1 refuses to start without a Cisco Networking Academy login.
#     Advanced Settings offers only internal-browser and proxy options — there
#     is no offline mode. This script therefore targets PT 7.x/8.x.
#   * PT 8.2.x is the last line that can run without a NetAcad account.
#
set -euo pipefail

PT_BIN="${1:?usage: $0 <pt-binary> <file.pkt> [outfile.png]}"
FILE="${2:?usage: $0 <pt-binary> <file.pkt> [outfile.png]}"
SHOT="${3:-/tmp/pt_verify.png}"
DISPLAY_NUM="${DISPLAY_NUM:-:99}"

if [ ! -x "$PT_BIN" ]; then echo "not executable: $PT_BIN" >&2; exit 2; fi
if [ ! -f "$FILE" ];   then echo "no such file: $FILE" >&2; exit 2; fi

# --- display -----------------------------------------------------------
if ! xdpyinfo -display "$DISPLAY_NUM" >/dev/null 2>&1; then
    Xvfb "$DISPLAY_NUM" -screen 0 1600x1000x24 >/tmp/xvfb.log 2>&1 &
    for _ in $(seq 1 30); do
        xdpyinfo -display "$DISPLAY_NUM" >/dev/null 2>&1 && break
        sleep 1
    done
fi
export DISPLAY="$DISPLAY_NUM"

# --- launch ------------------------------------------------------------
PT_DIR="$(dirname "$PT_BIN")"
export LD_LIBRARY_PATH="$PT_DIR:$PT_DIR/../lib:${LD_LIBRARY_PATH:-}"
LOG="$(mktemp /tmp/pt_verify.XXXXXX.log)"

setsid nohup timeout 180 "$PT_BIN" "$FILE" >"$LOG" 2>&1 </dev/null &
sleep 25

# Dismiss the "run multi-user" first-run dialog if it appears.
xdotool mousemove 989 488 click 1 2>/dev/null || true
sleep 15

import -display "$DISPLAY_NUM" -window root "$SHOT" 2>/dev/null || true

# --- verdict -----------------------------------------------------------
# Ignore the embedded web view's CSP/telemetry noise; look for real load faults.
ERRORS=$(grep -iE 'cannot open|corrupt|invalid file|failed to (load|open|read)|unable to read|file is not|bad (file|format)' "$LOG" \
         | grep -viE 'Content Security|doubleclick|linkedin|marketo|salesforce|netacad\.com|analytics' || true)

echo "log    : $LOG"
echo "shot   : $SHOT  ($(stat -c%s "$SHOT" 2>/dev/null || echo 0) bytes)"
if [ -n "$ERRORS" ]; then
    echo "verdict: FAILED - Packet Tracer reported a load error"
    echo "$ERRORS" | sed 's/^/  /'
    exit 1
fi
echo "verdict: no load errors reported by Packet Tracer"
echo "         confirm the topology visually in $SHOT"
