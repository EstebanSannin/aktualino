#!/usr/bin/env bash
#
# build.sh — host build + run of the Berry embedding spike (Aktualino S0).
#
# Proves the vendored Berry v1.1.0 (../berry) compiles and runs a single-.be
# "bundle" with the seed host API (log/report/gpio_set/health_ok) and the §8
# heartbeat confirm gate — with NO Aktualino or ESP-IDF dependencies. Runs
# anywhere with a C99 compiler + python3 (the coc codegen step).
#
# This mirrors the on-target build (SPEC/berry-secondary §6): coc generates the
# const-string table, then the Berry sources + our embedding driver are compiled.
#
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
berry="$here/../berry"
# Berry sources #include "../generate/..." with a literal relative path, so the
# codegen MUST land in berry/generate/ (adjacent to src/). It is gitignored.
gen="$berry/generate"
out="$(mktemp -d)"
trap 'rm -rf "$out" "$gen"' EXIT
mkdir -p "$gen"

: "${CC:=cc}"

echo "[coc] generating const tables -> $gen"
python3 "$berry/tools/coc/coc" -o "$gen" "$berry/src" "$berry/default" \
        -c "$berry/default/berry_conf.h"

echo "[cc]  compiling Berry + spike ($CC)"
"$CC" -std=c99 -Os -Wall -I "$berry/src" -I "$berry/default" \
      "$berry"/src/*.c "$berry"/default/be_modtab.c "$berry"/default/be_port.c \
      "$here/akt_berry_spike.c" -lm -o "$out/akt_berry_spike"

echo "[run]"
"$out/akt_berry_spike"
