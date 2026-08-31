# Aktualino — orientation & hard-won rules (for AI assistants and humans)

Aktualino is a small, from-scratch **full two-repo Uptane/TUF OTA client for the ESP32** (ESP-IDF)
that reuses ESP-IDF's native A/B OTA. It provisions to an OTA-Connect/Uptane backend and performs
cloud-driven, Uptane-verified A/B firmware updates with automatic rollback. The MVP (Phases 0–3 +
full two-repo verification) is complete and hardware-proven.

Start here: `README.md` (overview + proof points), `SPEC.md` (architecture + Appendix A device wire
protocol), `DEMO.md` (reproduce it), `docs/engineering-notes.md` (hard-won lessons),
`docs/torizon-cloud-validation.md`, `docs/provisioning.md`, `docs/hardening-todo.md`.

## Hard rules — do not violate

1. **Comments MUST stay consistent with the code — always. (Hard requirement.)**
   A comment that describes behavior the code no longer has is *worse than no comment*. Whenever you
   change code, in the **same change** update every comment, doc-comment, and any doc/SPEC text that
   describes it — never let a comment or doc drift from what the code actually does. Whenever you
   touch a function, re-read its surrounding comments and fix any that no longer hold. Prefer fewer,
   accurate, load-bearing comments over many that can rot. This applies to **every contributor,
   including AI agents and this file itself.**

2. **Torizon Cloud is the sole backend — it must be rock-solid.**
   Toradex's **Torizon Cloud** (`app.torizon.io` / device gateway `dgw.torizon.io`) is the backend
   Aktualino targets: prioritize it, test against it, and document it. It signs metadata with
   **RSASSA-PSS-SHA256 / RSA**; the device's own ECU manifest is signed **Ed25519**. The verify core
   supports both primitives (dispatched per key from the TUF `method`), and that must keep working.

3. **Never commit secrets.** `secrets/`, `credentials.zip`, `device.zip`, `*.pem`/`*.p12`/`*.sec`,
   private keys, API tokens, `wifi_credentials.h`, `provision_config.h`, generated NVS images, and
   `build*/` are gitignored — keep it that way, and never print secret values or access tokens in
   logs, commit messages, or output.

4. **Nothing irreversible without Stefano present.** Do NOT enable Secure Boot, flash/NVS encryption,
   anti-rollback, or any eFuse-burning option — they are permanent and can brick the board. App
   rollback (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`) burns nothing and is fine.

5. **No destructive cloud ops** on any backend (don't delete devices/packages/records).

## How we work
- SPEC/architecture first; **commit per small unit** with clear messages ending
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Never `git push` or create remotes
  without the maintainer's explicit go.
- **Build/flash via Docker on a build host** configured through `AKTUALINO_BUILD_HOST` /
  `AKTUALINO_BUILD_USER` / `AKTUALINO_SSH_KEY` / `AKTUALINO_SERIAL_PORT` (see `tools/sync-build.sh`):
  `docker` needs no sudo; flash through the `espressif/idf` container with the serial device.
  Author code locally; `rsync` to the build host; host tests run in throwaway containers.
- The Uptane core is **portable C** (cJSON + mbedTLS + libsodium): it must compile on host **and**
  both `esp32`/`esp32s3` targets, and the host test suite must pass, on every change.

_Keep this file updated as the project evolves — rule #1 applies to CLAUDE.md itself._
