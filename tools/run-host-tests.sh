#!/usr/bin/env bash
#
# run-host-tests.sh — build + run the portable-core host unit tests (CTest).
#
# These compile the SAME portable .c files the on-target components build
# (canonical JSON, Ed25519 + RSASSA-PSS verify, the meta-hash chain, the
# two-repo cross-verify and refuse paths), proving the Uptane security logic
# off-hardware. This is the gate the CI/release pipeline runs before publishing.
#
# Host toolchain + libs required (Debian/Ubuntu package names):
#   build-essential cmake libsodium-dev libcjson-dev libmbedtls-dev libssl-dev python3
# Install them locally, or run this inside a container, e.g.:
#   docker run --rm -v "$PWD":/src ubuntu:24.04 bash -c \
#     'apt-get update && apt-get install -y build-essential cmake libsodium-dev \
#      libcjson-dev libmbedtls-dev libssl-dev python3 && /src/tools/run-host-tests.sh'
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${1:-$REPO_ROOT/test/build}"

cmake -S "$REPO_ROOT/test" -B "$BUILD_DIR"
cmake --build "$BUILD_DIR" -j
ctest --test-dir "$BUILD_DIR" --output-on-failure
