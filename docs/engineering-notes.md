# Engineering notes — hard-won lessons

Distilled gotchas and decisions from building Aktualino's two-repo Uptane/TUF OTA
client for the ESP32 against Torizon Cloud. These are the things that were
non-obvious, cost real debugging time, or shape the design. Read alongside
`SPEC.md` (architecture + Appendix A wire protocol).

## Metadata verification

- **Canonical JSON must be byte-exact.** Every TUF signature is over
  `canonical(signed)`, so verification is only correct if the device reproduces
  the server's canonical form to the byte. The rule (OTA-Connect / circe
  `noSpaces`): recursively sort object keys ascending (bytewise == UTF-16 for the
  ASCII keys TUF uses), preserve array order, minify, escape strings as JSON, and
  emit integral numbers with no `.0`. `components/aktualino_crypto/akt_canonical.c`
  implements exactly this; `test_canonical` cross-checks it against a Python
  reference (`test/fixtures/gen.py`) on a nesting/ordering/escaping/UTF-8 sample.
  If the two disagree, every signature check fails — the cross-check is a
  first-class deliverable, not a nicety.

- **A TUF Ed25519 keyid is `sha256(SubjectPublicKeyInfo DER)`, hex.** For Ed25519
  the SPKI DER is a fixed 12-byte prefix + the 32 raw public-key bytes (44 bytes).
  The device derives its ECU keyid this way (`akt_keyid_ed25519`) so that the
  keyid on its manifest signature equals the keyid the Director derived from the
  registered public key — otherwise the Director rejects the manifest. The TUF key
  JSON still encodes the Ed25519 public as hex of the raw 32 bytes, not the DER.

- **Torizon Cloud signs with RSA, not Ed25519.** Every role (root/timestamp/
  snapshot/targets, both repos) is signed **RSASSA-PSS-SHA256 over an RSA-2048
  key**; the public key rides in the TUF key JSON as a PEM `SubjectPublicKeyInfo`.
  The verify path dispatches on the TUF `method` string per key
  (`akt_verify` → mbedTLS `pk_verify_ext` with `MGF1=SHA256`,
  `salt_len = ANY`), so the same core handles RSA and Ed25519 with no branching in
  the caller. The device's own manifest is still Ed25519 (on-device key).

- **The meta-hash chain rides the Image repo, not the Director.** The OTA-Connect
  Director **regenerates** its timestamp/snapshot/targets per request, so their
  bytes — and the mutual meta-hashes — vary between fetches; you cannot verify a
  `timestamp→snapshot→targets` chain against it. The Image repo (`/repo`,
  reposerver `user_repo`) is byte-stable, so the full chain is verified there. The
  Director is verified per-role instead (signature + threshold + expiry + version
  monotonicity). This is a property of the deployed server, not a client gap.

- **Hash the raw served bytes, not a re-serialization.** A meta-hash entry pins
  `sha256(child) == hashes.sha256` and `length == byte count`, where the bytes are
  the **whole `{signatures,signed}` envelope exactly as received on the wire**.
  Re-canonicalizing the child before hashing breaks the chain. `aktualino_net`
  hands the raw response buffer straight to `akt_verify_meta_link`.

- **Two independent trust anchors.** Director and Image are separate Uptane repos
  with their own root keys and their own NVS version namespaces, so their versions
  never collide. Both embedded roots (`main/embed/*_root.json`) are self-verified
  and pinned to NVS on first boot (TOFU-free). At provisioning the backend's real
  roots are seeded into NVS from `device.zip` and take precedence over the
  embedded ones (`trust_anchor_init` prefers the persisted root), so one firmware
  can target any account by replacing the seeded roots — the embedded roots are a
  fallback/placeholder.

## Provisioning against Torizon Cloud

- **`device.zip`, inflated on-device.** Torizon registration
  (`POST https://app.torizon.io/api/accounts/devices`, Bearer) returns a **ZIP**,
  not JSON. The device parses the ZIP central directory and inflates the DEFLATE
  members with the ROM `miniz` (`tinfl_decompress`, non-wrapping output buffer)
  to extract `client.pem`, `pkey.pem`, `root.crt`, `gateway.url`, and `info.json`
  (which carries `deviceUuid`). See `zip_extract` in `aktualino_prov.c`.

- **Access tokens are big JWTs.** A Torizon OAuth2 access token is a ~1.4 KB JWT;
  the `Authorization: Bearer` header overflows esp-http-client's default 512-byte
  request-header buffer. Size `buffer_size_tx` up (3 KB) on those calls, and size
  the header buffer from `strlen(token)` in `aktualino_prov`.

- **ECU serials are constrained.** The Director's `ValidEcuIdentifier` accepts
  alphabetic strings, length 10–64. The device derives its serial as
  `"aktualinoesp"` + MAC nibbles + nonce nibbles mapped to `a`–`p` (32 alphabetic
  chars) — proven-valid, and globally unique per board.

- **The identity nonce fixes re-provision collisions.** A persistent random nonce
  in NVS is folded into both the device name and the ECU serial. Re-enrolling a
  board (factory reset, wipe) then produces a fresh identity instead of colliding
  with the stale server-side record for the same MAC (SPEC §8).

- **Platform API v2 for assignment; watch the token scope.** The `credentials.zip`
  `garage-tools` client-credentials token is **repository-scoped** and 403s on
  every device-update/assignment path. A **user-scoped Platform API v2 client**
  (`tzn_api_…`) is authorized: `POST https://app.torizon.io/api/v2beta/updates`
  with `{"packageIds":[…],"devices":[<uuid>,…]}` takes up to 50 device UUIDs
  directly (no fleet needed) and returns an update id to poll at
  `/api/v2beta/updates/devices/{uuid}`.

## Download & install

- **Torizon serves binary targets via `302 → presigned S3`.** `GET
  /repo/targets/<name>` on the gateway returns an HTTP 302 to a presigned AWS S3
  URL, not a direct stream. The downloader must follow 30x on a **fresh** client;
  the S3 leg drops the pinned gateway CA + mTLS client cert and validates against
  the compiled public-CA bundle (`CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y`, FULL —
  Amazon root present). Capture `Location` via an `HTTP_EVENT_ON_HEADER` handler
  (the manual open/fetch-headers flow returns nothing from `get_header`), and
  raise `buffer_size_tx` (~4 KB) for the redirect leg (the ~1.5 KB SigV4 query
  overflows the default). Integrity is unaffected: the streamed bytes are still
  sha256+length verified against the two-repo target, so trusting the redirect leg
  is only defence-in-depth.

- **The install gate is sha256-based, and idempotent.** The single call site
  (`aktualino_core_download_and_install`) runs the cross-repo check first; there is
  no path from a Director assignment to a flash write unless **both** repos sign
  the identical `{filepath, sha256, length}`. Because the deployed Director does
  not always drop a processed assignment, the device compares the assigned target
  sha256 to the recorded running-image sha256 — so a re-listed old assignment logs
  "already installed — up to date" instead of reflashing.

- **Streaming SHA-256 into the A/B slot.** The download is fed straight into the
  inactive OTA partition while hashing; a corrupt/oversized target is rejected at
  `esp_ota_end`/length check and never boots, and a bad image that does boot is
  rolled back by the bootloader (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`).

## Platform / footprint

- **No RTC → SNTP every boot.** The boards have no battery-backed clock, so trusted
  time (which gates every role's `expires`) is re-established from SNTP on each
  boot, sanity-floored (2024-01-01) so a bogus clock can't defeat expiry checks.

- **Per-target flash budget.** The full two-repo client — two trust anchors,
  canonical JSON, Ed25519 + RSA-PSS verify, streaming download+hash, A/B OTA, and
  the SoftAP portal — fits with roughly **15% free** in the app slot on a classic
  ESP32 (4 MB, 1.5 MB `ota_*` slot) and **~59% free** on the ESP32-S3 (larger
  slot). Portable core code is shared, not duplicated per OTA slot.

- **One portable core, two build targets, host tests.** The security-critical
  logic (`akt_canonical.c`, `akt_crypto.c`, `akt_uptane.c`) is plain C with only
  cJSON + mbedTLS + libsodium — no `esp_err.h` — so the exact same source compiles
  for host unit tests and for both `esp32`/`esp32s3` targets. Keep it that way: it
  is what lets the verification logic be tested without hardware.
