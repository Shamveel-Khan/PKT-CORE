#!/usr/bin/env bash
# Build, repair, validate and document the JASDF AEW&C Packet Tracer model.
#
#   ./run_all.sh [profile]        profile = smoke | standard | enterprise (default)
#
# The enterprise profile writes the canonical docs/ artefacts; other profiles
# are suffixed so they never clobber them.
#
# This package contains only the MODEL.  The format toolkit (pkt-core:
# tools/lab_api.py, tools/finalise_lab.py, src/pkt_core) is a separate checkout.
# Set PKT_TOOLKIT to it, or place this directory inside it -- the script
# searches upwards before giving up.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PY:-python3}"
PROFILE="${1:-enterprise}"

# ---- locate the toolkit ----------------------------------------------------
if [ -z "${PKT_TOOLKIT:-}" ]; then
  for cand in "$ROOT" "$ROOT/.." "$ROOT/../.." "$ROOT/../../.."; do
    if [ -f "$cand/tools/lab_api.py" ] && [ -d "$cand/src/pkt_core" ]; then
      PKT_TOOLKIT="$(cd "$cand" && pwd)"
      break
    fi
  done
fi
if [ -z "${PKT_TOOLKIT:-}" ]; then
  cat >&2 <<'EOF'
error: cannot find the pkt-core toolkit (tools/lab_api.py + src/pkt_core).

This package builds a lab; the toolkit does the encoding.  Clone it and point
PKT_TOOLKIT at the checkout:

    git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
    PKT_TOOLKIT=/path/to/packet-tracer-pkt-format ./run_all.sh

Inside the toolkit the source tree ships as generators/jasdf_aewc/, where the
upward search finds it automatically.
EOF
  exit 1
fi
export PKT_TOOLKIT
echo "toolkit : $PKT_TOOLKIT"
echo "python  : $($PY -c 'import sys; print(sys.executable)')"

# fail loudly and early if the toolkit is not importable by this interpreter
"$PY" - <<'EOF'
import sys, os
sys.path[:0] = [os.environ["PKT_TOOLKIT"], os.path.join(os.environ["PKT_TOOLKIT"], "src")]
try:
    import pkt_core  # noqa: F401
except Exception as exc:  # pragma: no cover - diagnostic path
    raise SystemExit(
        f"error: this python cannot import pkt_core from {os.environ['PKT_TOOLKIT']}/src "
        f"({exc}).\n       Install the toolkit first:  pip install -e {os.environ['PKT_TOOLKIT']}"
    )
EOF

if [ "$PROFILE" = "enterprise" ]; then SFX=""; else SFX="_$PROFILE"; fi
OUT="out/JASDF_AEWC_JADGE${SFX}.pkt"

echo
echo "== build ($PROFILE) =="
"$PY" build_jasdf_aewc.py --profile "$PROFILE" --out "$OUT"

# The generator now lays devices out through lab_api.Layout and derives unique
# DHCP pool names, so this pass *should* be a no-op.  It is kept because it is
# the verification gate: it re-checks that nothing overlaps and nothing is off
# the page, that no template service record survived, that every printed count
# is of distinct items and free of leftovers, and that the result re-encodes
# byte-exactly.  It exits non-zero if any of that fails.
#
# No --rename-pools: the generator handles pool names itself.  pool_renames.json
# exists to migrate files built by the OLDER generator; applying it here is not
# merely unnecessary -- a profile that legitimately lacks one of the two sites
# (smoke has no site 29) matches no pool, and the tool correctly refuses to
# guess rather than silently do nothing.
#
# --update-report keeps the build report honest.  It is a no-op while the
# generator and this pass agree, but the moment anything downstream edits the
# file, size_bytes and sha256 would otherwise describe a file that no longer
# exists.
echo
echo "== gate: layout, leftovers, distinct counts, round-trip =="
"$PY" "$PKT_TOOLKIT/tools/finalise_lab.py" \
      --templates "$PKT_TOOLKIT/tools/device_templates.json" \
      --update-report "build/report_${PROFILE}.json" \
      "$OUT"

echo
echo "== validate =="
"$PY" validate.py "$OUT"

echo
echo "== gate: layout =="
"$PY" "$PKT_TOOLKIT/tools/check_layout.py" "$OUT"

echo
echo "== gate: service counts are distinct =="
"$PY" -m pkt_core.cli.main audit "$OUT" \
      --templates "$PKT_TOOLKIT/tools/device_templates.json"

echo
echo "== diagram =="
"$PY" tools/draw_topology.py "$OUT" "docs/img/topology${SFX}.svg"
if command -v convert >/dev/null 2>&1; then
  convert -density 96 -background white "docs/img/topology${SFX}.svg" \
          -resize 2100x "docs/img/topology_overview${SFX}.png"
else
  echo "  (skipped PNG: ImageMagick 'convert' not found)"
fi

echo
echo "== as-built documentation =="
"$PY" tools/export_plan.py "$OUT" "$SFX"

echo
echo "== hashes =="
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$OUT" | tee "build/final_sha256${SFX}.txt"
else
  shasum -a 256 "$OUT" | tee "build/final_sha256${SFX}.txt"
fi

echo
echo "done -> $OUT"
