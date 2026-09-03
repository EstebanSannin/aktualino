# Torizon Cloud validation

Aktualino is validated end-to-end against **real Torizon Cloud** (`app.torizon.io`
/ `dgw.torizon.io`): provision, on-device RSA two-repo verify, target publish,
assignment via the Platform API v2, mTLS+redirect download, A/B install, reboot,
`mark_valid`, and a success manifest that Torizon Cloud records as **Completed /
OK / success**. This document summarizes the flow and the confirmed results.

## The device protocol is the OTA-Connect protocol

Torizon Cloud runs the OTA-Connect/Uptane stack, so the device-facing gateway
protocol is the one Aktualino implements: ECU registration (`POST /director/ecus`),
Director + Image-repo metadata verification (canonical JSON, signature threshold,
expiry, rollback), the V3 manifest, target download (`GET /repo/targets/…`), and
the two-repo cross-verified A/B update. Torizon signs every role with
**RSASSA-PSS-SHA256 / RSA-2048**; the verify core dispatches the primitive per key
from the trust-anchor root, so nothing in the update engine is backend-specific.

## Provisioning shape

Torizon device registration is OAuth2 client-credentials → `POST
https://app.torizon.io/api/accounts/devices {device_id, device_name}` (Bearer) →
a **`device.zip`** carrying the per-device cert/key + server CA + gateway URL +
`info.json` (`deviceUuid`). The two trust-anchor roots (Director + Image
`root.json`) come from `credentials.zip`. `aktualino_prov_torizon_fetch_creds`
does this on-device (inflating `device.zip` with the ROM miniz); the host injector
`tools/aktualino-provision.py --torizon` does the same into an NVS image.

The trust anchor is seeded from NVS (`trust_anchor_init` prefers the persisted
root over the firmware-embedded root, still TOFU-free because a trusted source
provides it), so one firmware image can target any account.

## Test procedure

1. **Provision** (host tool or on-device portal): register the device, get
   `device.zip`, store creds + the Torizon Director/Image roots.
2. **Enrol on-device:** Wi-Fi + SNTP → ECU register → first manifest → the device
   appears in the Torizon Cloud console.
3. **Verify metadata:** poll → Director **and** Image-repo roles verify against
   Torizon's live RSA keys (root-rotation, expiry via SNTP) → "no update assigned".
4. **Publish + assign** a binary target `<hwid>-<newver>` for the hardware id, and
   assign it to the device.
5. **Update:** poll → two-repo cross-verify → download over mTLS (following the
   redirect) → sha256/length verify → A/B flash → reboot → `mark_valid` → success
   manifest with the correlation id → Torizon Cloud shows the update completed.

## Confirmed results (real Torizon Cloud)

Prerequisites: a Torizon Cloud `credentials.zip` (Developer tier+), the ability to
publish + assign a binary target for a chosen `hardwareId` (e.g. `aktualino-esp32`),
and a Wi-Fi network with internet to reach `app.torizon.io`.

- **RSA metadata verify (host):** `test/test_torizon_metadata.c` verifies both
  anchor roots' self-signatures, every Director + Image role, and the Image
  meta-hash chain against Torizon-shaped RSA metadata.
- **Provision on hardware:** device flashed with an injected NVS image →
  Wi-Fi + SNTP → ECU self-register → first manifest (200). Confirmed in Torizon
  Cloud via the Director admin API: the device's ECU (primary, hwid
  `aktualino-esp32`) with installed image `aktualino-esp32-0.1.0`.
  `test/evidence/torizon-provision.log`.
- **Live metadata verify (RSA, on-device):** persisted Director + Image roots
  self-verify; timestamp/snapshot/targets VERIFY PASS against Torizon's RSA keys;
  expiry via SNTP; "no update assigned". `test/evidence/torizon-stage4-metadata.log`.
- **Publish:** a BINARY target uploaded to the reposerver user_repo (`PUT
  .../user_repo/targets/<name>?…&targetFormat=BINARY`, octet-stream) → 204, online
  RSA signing; `user_repo/targets.json` re-signed with the sha256/length.

### Assignment auth (Platform API v2)

The `credentials.zip` `garage-tools` client-credentials token is **repository-scoped**
and 403s on every device-update/assignment path. A **user-scoped Platform API v2
client** (`tzn_api_…`, `secrets/torizon/api-client.json`, same OAuth2
client_credentials endpoint) is authorized:

```
POST https://app.torizon.io/api/v2beta/updates
{"packageIds":["aktualino-esp32-0.2.0"], "devices":["<device-uuid>"]}
-> 201  {"affected":[{"deviceUuid":"<device-uuid>", …}],"notAffected":[]}
```

`devices` takes up to 50 device UUIDs directly — no fleet required. Poll the update
id at `GET /api/v2beta/updates/devices/{uuid}` (Assigned → Seen → Completed).

### Following the target redirect

Torizon serves a BINARY target as **HTTP 302 → a presigned AWS S3 URL**, not a
direct stream. `aktualino_net_get_stream` follows a 30x on a fresh client; the S3
leg drops the pinned gateway CA + mTLS client cert and validates against the
compiled public-CA bundle (`CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y`, FULL); it
captures `Location` via an `HTTP_EVENT_ON_HEADER` handler and raises
`buffer_size_tx` for the ~1.5 KB SigV4 query. Integrity is unchanged — the streamed
bytes are still sha256+length verified against the two-repo target.

### Full install (real hardware, classic ESP32)

poll → target ASSIGNED `aktualino-esp32-0.2.0` → Image-repo RSA verify +
`CROSS-REPO MATCH PASS` → GET target → 302 → bundle-CA S3 leg → S3 GET 200 →
`install: VERIFIED sha256 + length OK` → boot slot set → reboot → running new
version (PENDING_VERIFY) → SNTP → `running image marked valid` → success
installation_report `PUT /director/manifest` → 200 ACCEPTED → **UPDATE COMPLETE**.
Next poll: "already installed — up to date (idempotent)".

Confirmed in Torizon Cloud (Platform API v2): device `deviceStatus: UpToDate`,
installed image `aktualino-esp32-0.2.0`; update **status Completed, deviceResult
{resultCode: OK, success: true}**. Evidence:
`test/evidence/torizon-update-complete.log` (on-device serial) +
`test/evidence/torizon-update-backend.log` (API request/response).

## Validated on ESP32-S3 silicon (not just the classic ESP32)

The flow above was first proven on the classic ESP32. It is now also
hardware-proven on a real **ESP32-S3** (QFN56, rev v0.2, 8 MB PSRAM, 8 MB flash),
including the optional **Berry script secondary** — the S3-first feature — end to
end over real Torizon Cloud:

- **First-silicon bring-up** — feature-on image (`CONFIG_AKTUALINO_SCRIPT_SECONDARY=y`)
  boots on the S3: 8 MB octal PSRAM initialized, `berry v1.1.0 up`, running on
  `ota_0` (VALID), `scripts` partition mounted. `test/evidence/esp32s3-bringup.log`.
- **Provisioned to Torizon Cloud** — a fresh device (UUID `90ff467f-…`) self-
  registers **both** ECUs (primary `aktualino-esp32`, secondary `aktualino-lua`);
  first V3 manifest ACCEPTED. `test/evidence/esp32s3-torizon-register.log`.
- **Berry bundle delivered OTA** — `aktualino-lua-1.4.0` (blink) published + assigned
  to the secondary; the S3 does `CROSS-REPO MATCH PASS` → 302 → S3 GET →
  install to the `scripts` partition → the Berry VM runs `setup()`/`loop()` and
  reports. `test/evidence/esp32s3-berry-install.log`.
- **Torizon Cloud records it Completed** — update `01a0619f-…` **status Succeeded,
  deviceResult {resultCode: OK, success: true}**.
  `test/evidence/esp32s3-berry-backend.log`.

Note: the firmware currently reports the primary hardware id as `aktualino-esp32`
on both chips (it is not chip-derived); a distinct `aktualino-esp32s3` primary id
is a small, tracked follow-up. It does not affect the Berry secondary (hwid
`aktualino-lua`).
