# Vendored Berry VM

This directory is a **pristine subset of upstream [Berry](https://github.com/berry-lang/berry)**,
the ultralight embedded scripting language (register-based VM, ANSI C99). It is the runtime for the
Aktualino script secondary (`docs/berry-secondary-spec.md`).

Keep this tree upstream-faithful: **do not hand-edit `src/` or `default/`.** Aktualino's own code
(the embedding wrapper, host API bindings, CMake, Kconfig) lives in the **parent** component
directory, not here. That way bumping to a new Berry release is a clean re-copy.

## Pinned version

- **Release:** `v1.1.0`
- **Upstream commit:** see `COMMIT` (`b5ede66721937533fbf5c286ef44a5111ea30c75`)
- **License:** MIT — see `LICENSE` (© 2018–2020 Guan Wenliang). Compatible with Aktualino.

## What is included (and what is not)

| Path | From upstream | Purpose |
|---|---|---|
| `src/*.c`, `src/*.h` | `src/` (all 66 files) | the VM, compiler, GC, and built-in libs |
| `default/berry_conf.h` | `default/` | build-time configuration (see below) |
| `default/be_modtab.c` | `default/` | the built-in module table |
| `default/be_port.c` | `default/` | platform port (stdout, malloc, time…) — adapted for ESP-IDF later |
| `tools/coc/` | `tools/coc/` | the compile-time codegen (see below) |
| `LICENSE`, `COMMIT` | — | provenance |

**Deliberately excluded:** `default/berry.c` (the standalone REPL `main()` with readline — we embed,
we don't run the REPL), `examples/`, `tests/`, `.git`, logo/docs.

## The codegen step (`coc`)

Berry keeps its built-in constants in a generated const-string table. `tools/coc/coc` (Python 3)
scans `src/` + `default/` and emits headers that the sources `#include "../generate/..."` — a
**literal relative path**, so the output must land in **`generate/`** here (adjacent to `src/`).
`generate/` is **gitignored** (build output, never committed). Both build paths regenerate it:

- **Host test:** `test_host/build.sh` runs `coc` into `generate/`, compiles, runs, and cleans up.
- **On-target (ESP-IDF):** the parent `CMakeLists.txt` runs `coc` as a build step (S0.2), the same
  python-codegen-as-build-step pattern already used by `test/CMakeLists.txt`.

## Updating to a newer Berry

1. Clone the new tag, copy `src/`, the three `default/` files, and `tools/coc/` over this tree.
2. Update `COMMIT` and the version above.
3. Re-run `test_host/build.sh` (must stay green) and the on-target build.
4. Re-check `default/berry_conf.h` against our overrides (we override it from the parent, not by
   editing this file — see the parent component).
