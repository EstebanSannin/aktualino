#!/usr/bin/env bash
#
# run.sh — validate an Aktualino Berry bundle on your laptop (no ESP32).
#
#   examples/run.sh examples/bundles/blink.be [loops]
#
# Compiles the vendored Berry VM + the embedding wrapper + host-run.c and runs
# your bundle through setup() + a few loop() cycles with stub host functions, so
# you catch syntax/logic errors before publishing. Needs a C99 compiler + python3
# (Berry's coc codegen). See docs/bundles.md.
#
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
berry="$here/../components/aktualino_berry/berry"
conf="$here/../components/aktualino_berry/conf"
wrap="$here/../components/aktualino_berry"

bundle="${1:?usage: run.sh <bundle.be> [loops]}"
loops="${2:-12}"

gen="$berry/generate"
out="$(mktemp -d)"
trap 'rm -rf "$out" "$gen"' EXIT
mkdir -p "$gen"

: "${CC:=cc}"
python3 "$berry/tools/coc/coc" -o "$gen" "$berry/src" "$berry/default" -c "$conf/berry_conf.h"
"$CC" -std=c99 -Os -w -I "$conf" -I "$berry/src" -I "$wrap/include" \
      "$berry"/src/*.c "$berry"/default/be_modtab.c "$berry"/default/be_port.c \
      "$wrap/aktualino_berry.c" "$here/host-run.c" -lm -o "$out/host-run"
"$out/host-run" "$bundle" "$loops"
