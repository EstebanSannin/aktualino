# Aktualino — a tiny Uptane update client for the ESP32

> _This is the design spec. It was written before the code and kept as the architecture reference;
> a few sections still carry their original `ASSUMPTION (confirm)` notes, reconciled against the live
> backend in the "Status: as-built" block below._

> ## Status: as-built
>
> **The MVP is complete and hardware-proven.** Phases 0, 1, 2, 3 and **4a** (full two-repo Uptane)
> are DONE on a classic ESP32 against **real Torizon Cloud**, with a full cloud-driven update
> installed through a Director+Image-repo cross-verified path. See `README.md` for the proof points,
> `DEMO.md` to reproduce it, `docs/engineering-notes.md` for the lessons, and `test/evidence/*.log`
> for the captures. Reconciliations to the pinned assumptions below, confirmed live:
>
> - **keyid + Ed25519 encoding — CONFIRMED.** ECU `keyid = hex(sha256(Ed25519 SPKI-DER))`
>   (matches the OTA-Connect ota-tuf keyId); `keyval.public` = **hex of the raw 32 pubkey bytes**,
>   `keytype: "ED25519"`. Verified empirically (recomputed keyid == the registered pubkey's).
> - **Metadata sig type — CONFIRMED RSA.** Torizon Cloud signs every role with
>   **RSASSA-PSS-SHA256 / RSA-2048**; the device verified live Director + Image roles against
>   Torizon's RSA keys with no code changes. The verify core also handles Ed25519 (dispatched per
>   key from the TUF `method`); the device's own ECU manifest is Ed25519.
> - **Meta-hash semantics — CONFIRMED, with a nuance.** `parent.meta[child].hashes.sha256 ==
>   sha256(raw served bytes of the child envelope)` — so the device hashes the body as received.
>   **But** the Director regenerates ts/snap/targets per request (unstable bytes), so the
>   `ts→snap→targets` hash **chain** is verified against the **Image repo** (stable bytes); the
>   Director is verified per-role (sig+threshold+expiry+version).
> - **Provisioning — CONFIRMED (Torizon Cloud device.zip).** OAuth2 client-credentials →
>   `POST /accounts/devices` → `device.zip` (per-device mTLS cert/key + CA + gateway), inflated
>   on-device; the Ed25519 ECU signing key is separate and generated on-device. On-device keygen +
>   `/devices` CSR is deferred (`docs/hardening-todo.md`).
> - **ECU serial — CONFIRMED valid** as alphabetic length-10–64 (`"aktualinoesp"+MAC/nonce→a..p`).
> - **Target storage — CONFIRMED.** Torizon serves a binary target as **HTTP 302 → presigned S3**;
>   the downloader follows the redirect and validates the S3 leg against the public-CA bundle.
> - **On-hardware target = classic ESP32 only** (CH340 `/dev/ttyUSB0`); ESP32-S3 is compile-clean
>   every phase but was not physically connected.
> - **No irreversible options enabled** (no Secure Boot / flash encryption / anti-rollback eFuse);
>   only `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`. Keys/TUF metadata live in **plaintext NVS** today
>   (§8's "encrypted NVS" is deferred — see `docs/hardening-todo.md`).

Aktualino ("little aktualizr", the Italian `-ino`) is a minimal, security-preserving
[Uptane](https://uptane.github.io/)/[TUF](https://theupdateframework.io/) update client for
Espressif microcontrollers (ESP32 / ESP32-S3), built on **ESP-IDF**. It provisions a device to
**Torizon Cloud** and applies over-the-air firmware updates by reusing **ESP-IDF's native A/B OTA**
mechanism.

It is **not** a port of aktualizr's source (Boost, curl, sqlite, OSTree — none of it fits an MCU).
It is a clean reimplementation of the Uptane *client logic* against the same wire protocol, sized
for a device with a few hundred KB of RAM and a few MB of flash.

---

## 1. Goals & non-goals

### Goals (what "done" means over the whole project)
- Provision an ESP32 to **Torizon Cloud** (the OTA-Connect/Uptane reference cloud).
- Receive an update assignment, download a **plain binary** firmware target chosen by **hardware
  id**, verify it, and flash it into the inactive A/B slot via ESP-IDF OTA.
- Boot the new image, self-confirm, and **roll back automatically** on failure.
- Report an Uptane **device manifest** (installed version, result) back to the director.
- Progressively add **genuine Uptane metadata verification** (Director role, then Image repo) so the
  device only trusts correctly-signed, non-rolled-back, non-expired updates.

### Non-goals (at least for v1)
- OSTree / delta updates (ESP-IDF apps are monolithic `.bin`; no OSTree on an MCU).
- Secondary-ECU orchestration, multi-ECU vehicles.
- The management/REST API surface (Torizon API 2.0) — Aktualino is a **device**, it speaks the
  **device gateway** protocol only.
- Remote access (RAC), metrics/telemetry pipelines, lockbox/offline updates (possible later).
- Production key ceremony / HSM. MVP uses on-flash key storage (see §8).

---

## 2. One OTA-Connect device protocol

Toradex **Torizon Cloud** runs the **OTA-Connect/Uptane** stack: `ota-tuf` (reposerver +
keyserver), `director`, `treehub`, a device **gateway** (mTLS), and device provisioning. Aktualino
speaks the **device-gateway** side of that protocol. Because the protocol is the same across any
OTA-Connect deployment, the update engine has no backend-specific code — only provisioning differs,
and that is isolated in `aktualino_prov`.

---

## 3. System context (topology: **standalone Primary**)

The ESP32 is a **full/standalone Uptane Primary** — it is the only ECU and talks to the cloud
directly. (Uptane's *partial-verification secondary* role would be lighter, but we chose the
standalone-primary shape to match "provision the ESP32 to the cloud" directly.)

```
   ┌─────────────┐   WiFi    ┌──────────────────────────────────────────┐
   │  ESP32 /    │◀────────▶ │  Device Gateway (mTLS, dgw.torizon.io)    │
   │  ESP32-S3   │   TLS 1.2 │   ├─ /director/...   (Uptane Director)    │
   │  Aktualino  │  + client │   ├─ /repo/...       (Uptane Image repo)  │
   │             │    cert   │   └─ /repo/targets/… (binary download,    │
   └─────────────┘           │                        302 → presigned S3)│
         │                   └──────────────────────────────────────────┘
         │  reuses
         ▼
   ESP-IDF OTA:  ota_0 / ota_1  +  otadata (slot select + rollback)
```

The device authenticates with its **mTLS client cert only** — the gateway derives the device UUID
from the client-cert **CN**, injects `x-ats-namespace: default`, and disables gzip (so TUF hashes
match exact bytes). The device never sends a namespace header or bearer token on director/repo calls.
It pins the **server CA** delivered at provisioning time; the gateway server-cert CN is the gateway
host (`dgw.torizon.io` on Torizon Cloud). Full path map in **Appendix A**.

---

## 4. aktualizr → Aktualino gap analysis

| aktualizr does… | On the ESP32 we… | Change |
|---|---|---|
| Provision via credentials.zip + on-device CSR to `/devices` | Register via `POST /accounts/devices` → **`device.zip`** (per-device cert+key delivered) | Simpler; on-device CSR is a deferred hardening item (see §8) |
| Full Uptane: Director **and** Image repo, all 4 roles | Stage it: pipeline first (Phase 1/3), Director verification (Phase 2), Image repo (Phase 4) | Staged, not skipped |
| Download an **OSTree** commit from treehub | Download a **binary `.bin`** target from the reposerver via gateway | Fundamental — MCU has no OSTree |
| Install via OSTree deploy + U-Boot | `esp_ota_write` into inactive slot; `otadata` flips active slot on reboot | Reuse ESP-IDF A/B |
| Rollback via bootloader deployments | ESP-IDF **app rollback** + **anti-rollback** (`secure_version`) | Reuse ESP-IDF |
| Sign & send device manifest to Director | Same — sign a manifest with the ECU key, `PUT` to `/director/manifest` | Direct port of the *logic* |
| Boost/curl/sqlite/glib | esp-tls/mbedTLS + libsodium + cJSON + NVS | Reimplement lean |

---

## 5. Architecture — modules

Each is an ESP-IDF component with a narrow C API. Boundaries are chosen so security-critical code is
small and testable, and so hardware-specific pieces (key storage, OTA) sit behind interfaces.

```
components/
  aktualino_core/     orchestrator: state machine, poll loop, config
  aktualino_net/      esp-tls mTLS client to the gateway (GET/PUT, streaming download)
  aktualino_prov/     provisioning: fetch device.zip, store creds, ECU self-register + manifest
  aktualino_uptane/   metadata: canonical-JSON, role parse/verify, targets selection, manifest build
  aktualino_crypto/   verify (Ed25519 + RSASSA-PSS-SHA256), hash (SHA-256), sign (manifest)
  aktualino_store/    persistence: NVS-backed creds + TUF metadata store + install state
  aktualino_ota/      ESP-IDF OTA wrapper: write inactive slot, verify, set-boot, confirm/rollback
  aktualino_time/     secure time (SNTP + sanity vs metadata expiry)
main/                 app entry, WiFi bring-up, wiring
```

### State machine (core)
```
BOOT → TIME_SYNC → (PROVISIONED?) ─no─▶ PROVISION ─┐
                        │yes                        │
                        ▼                           │
             POLL_DIRECTOR ◀───────────────────────┘
                        │ assignment for our hw id?
             ┌──no──────┤
             │          │yes
             │          ▼
             │   VERIFY_METADATA → DOWNLOAD → VERIFY_IMAGE → INSTALL(inactive) → REBOOT
             │                                                                     │
             │                                              (new image) CONFIRM ──┤ok→ REPORT_OK
             │                                                     │fail            └→ ROLLBACK→REPORT_FAIL
             └──▶ REPORT_MANIFEST (current state) ──▶ sleep(poll_interval) ──▶ POLL_DIRECTOR
```

---

## 6. Provisioning flow (Phase 1)

Torizon Cloud device provisioning:

1. **Register the device.** OAuth2 `client_credentials` (from the `credentials.zip`
   `provision.json`) → an access token → `POST https://app.torizon.io/api/accounts/devices`
   `{ device_id, device_name }` with `Authorization: Bearer <token>` → a **`device.zip`**.
2. **Unpack** `device.zip` → `{ client.pem, pkey.pem, root.crt (server CA), gateway.url, info.json
   (deviceUuid) }` — the per-device mTLS identity + pinned server CA. On-device this is inflated
   with the ROM miniz; a host injector unpacks it into an NVS image.
3. **Persist** into NVS via `aktualino_store`: device cert, device key, server CA, gateway URL,
   device UUID, plus the Director + Image `root.json` trust anchors from `credentials.zip`.
4. **ECU-register with the Director** (**PINNED** — `POST /director/ecus`, Appendix A). Generate the
   Uptane **ECU signing keypair** (**Ed25519**) on device and POST `{ primary_ecu_serial,
   ecus:[{ ecu_serial, hardware_identifier, clientKey }] }` → `201`/`200`. This is a **separate,
   explicit call the device makes before its first manifest** — it hands the device's Uptane public
   key to the director. The TLS device cert (step 2) and the Uptane ECU key (**Ed25519, on-device**)
   are **distinct** keys.
5. **First manifest** `PUT /director/manifest` (Appendix A) establishes the device as "current" in
   the console (~20 s to appear).

The classic on-device-CSR `/devices` flow (key never leaves the chip) is a deferred improvement
(`docs/hardening-todo.md`).

**Hardware id.** Register a dedicated hw id (e.g. `aktualino-esp32`) so binary targets can be
published against it without colliding with real Torizon boards.

### 6.1 Provisioning UX — getting creds onto a shell-less device

The Linux flow (`curl … | sudo bash`) works because Linux has a shell. The ESP32 has none, so the
enrolment inputs (**gateway/server URL + enrolment token + WiFi SSID/pass**) must arrive another
way. Firmware stays **byte-identical across all boards**; only per-device bits live in a small
**NVS blob**. There is **one NVS credential schema** and several interchangeable "injectors" that
write it, so no approach locks us in.

**Chosen model: a first-boot wizard collects the inputs; the device self-enrols** (compose of the
"runtime wizard" + "self-enrol token" ideas — they are not alternatives: the wizard is the *input
method*, self-enrol is the *device behavior*). This mirrors Torizon's **provision-at-scale**.

**Credential model (Torizon Cloud):** device registration is a `credentials.zip`
`provision.json` client (OAuth2 `client_credentials`). Three ways to give a board that credential
(see `docs/provisioning.md`): the host registers per-device and injects only the resulting
`device.zip` identity (most secure); the `provision.json` client is baked so each board
self-registers (dev-only, needs flash encryption); or the operator pastes a provisioning token from
their own account into the portal at setup. A registration returns a `device.zip` whose `root.crt`
pins the gateway for the subsequent mTLS.

**Injectors (all write the same NVS schema):**

| Injector | Transport | When | Notes |
|---|---|---|---|
| **SoftAP captive portal** (default product UX) | device SoftAP + browser | field / non-dev | build on ESP-IDF `wifi_provisioning` (SoftAP); add a **token** field to its custom-data endpoint. No app install; testable from any laptop/phone browser |
| **BLE wizard** (later) | device BLE + app or desktop CLI | field / mobile | same `wifi_provisioning` framework, BLE transport; avoids the "join AP then rejoin WiFi" dance |
| **Host CLI** (dev fast-path **and shipped tool**) | USB serial → NVS image | Phase 0–3 iteration + release | `tools/aktualino-provision.py` writes the NVS blob directly (or does host mint-and-flash). Not dev-only — **released as a supported injector** so CLI-preferring users never have to use a graphical/SoftAP portal |

The graphical wizard (SoftAP/BLE) and the **headless CLI** are **both first-class, released** paths,
not tool-vs-toy: some users will always prefer a scriptable command over clicking. They share one
NVS schema, so neither is second-class.

**Build order:** implement the **NVS schema + self-enrol code path first** (drivable by the host CLI
in seconds), *then* put the SoftAP portal in front of it. Wizard, BLE, and CLI are just three faces
of the same underlying enrolment.

**Two device keys, don't conflate them:** the minted **P-256 cert/key** is TLS-only (mTLS to the
gateway). The **Uptane ECU signing key** (for the device manifest) is separate and generated on
device (§6 step 4).

**Security corners (designed in from the start):**
- Provisioning NVS lives in an **encrypted NVS partition** (flash encryption + NVS keys); MVP may
  start plaintext and enable encryption in Phase 1/4.
- The token crosses the local link → rely on `wifi_provisioning` **session encryption** (X25519+AES,
  works even over an open AP) + a **proof-of-possession / per-device AP password** so a bystander
  can't open the portal.
- Self-enrol means the ESP **receives** its minted private key over the provision channel (same
  trust model as the Linux one-liner). On-device keygen + `/devices` CSR (key never leaves the chip)
  is the **Phase-4** hardening variant.
- A **factory-reset-to-AP** trigger (button-hold / N failed enrols) re-opens the wizard **and**
  clears the stored TUF metadata namespace — this doubles as the stale-root reset from §8.
- WiFi creds live in the **NVS blob, never in firmware source** — sharing an SSID/pass is just
  regenerating one device's blob.

---

## 7. Update flow (Phases 2–3)

All device paths below are **relative to the gateway** (`https://dgw.torizon.io`), which rewrites
`/director/*` → director and `/repo/*` → image repo and authenticates by the **mTLS client cert
only**. Responses are never gzipped, so TUF hashes match exact bytes. Full path/shape reference in
**Appendix A**.

1. **Poll Director.** `GET /director/root.json` (+ `GET /director/{N}.root.json` to walk a root
   rotation), then `timestamp.json` → `snapshot.json` → `targets.json`. For MVP the meaningful check
   is the **Director `targets.json`** assignment for our ECU serial.
2. **Verify metadata** (`aktualino_uptane` + `aktualino_crypto`):
   - **canonical JSON** of the `signed` sub-object as signature input — recursive key-sort, arrays
     untouched, minified, numbers byte-preserved, UTF-8 (Appendix A; the classic TUF gotcha — must
     be byte-exact),
   - signature threshold against role keys from `root.json` (**Ed25519** by default),
   - **expiry** (`signed.expires`, needs secure time §9),
   - **version monotonicity** (rollback protection on metadata).
3. **Select target** matching our `hardware_identifier`; read `length` + `sha256` + custom fields
   (version, `esp_app_desc`).
4. **Download** streaming from `GET /repo/targets/<path>` via the gateway — `application/octet-stream`
   streamed through the reposerver on managed storage (an S3-backed target may instead answer `302`
   to an external URI — handle both). Hash **while streaming** into the inactive OTA slot — never
   buffer a whole image in RAM.
5. **Verify image**: computed SHA-256 == targets hash, length matches, and `esp_app_desc` version ≥
   anti-rollback `secure_version`.
6. **Install**: `esp_ota_begin/write/end` on the inactive partition; `esp_ota_set_boot_partition`.
7. **Reboot** → new app boots **pending-verify**; on success `esp_ota_mark_app_valid_cancel_rollback`,
   else the bootloader rolls back automatically.
8. **Report**: build the **V3 device manifest** (Appendix A) — `primary_ecu_serial` +
   `ecu_version_manifests{ <serial>: SignedPayload[EcuManifest] }` + optional `installation_report`.
   The ESP signs **twice with its one Ed25519 ECU key** (inner `EcuManifest` + outer envelope);
   `PUT /director/manifest`.

**Correctness-first (MVP) staging.** Per our decision "working OTA loop first": Phase 1+3 get the
full pipeline running with **TLS trust + image hash/signature** only; Phase 2 adds the strict
Director role verification; Phase 4 adds the Image-repo cross-check (Snapshot/Timestamp/Targets) for
full two-repo Uptane.

---

## 8. Security model

### Crypto primitives
| Purpose | Primitive | Library |
|---|---|---|
| TLS to gateway (mutual) | TLS 1.2, **EC P-256** client cert | esp-tls / **mbedTLS** (HW-accelerated AES/SHA) |
| Metadata signature verify | **Ed25519** (default) + **RSASSA-PSS-SHA256** (fallback) | **libsodium** (Ed25519) + mbedTLS (RSA-PSS) |
| Image + metadata hashing | SHA-256 | mbedTLS (ESP32 HW SHA) |
| Manifest / ECU key signing | Ed25519 | libsodium |

**PINNED (from `libats`/`ota-tuf` source):** `KeyType.default = Ed25519`, so a fresh instance signs
**every server role with Ed25519** (`method: "ed25519"`) — *not* RSA. The server's own verifier
accepts **only** `ed25519` and `rsassa-pss-sha256` (`ecPrime256v1` is rejected). So Aktualino makes
**Ed25519 the primary verify path** (libsodium) and keeps **rsassa-pss-sha256** (mbedTLS) as a
secondary for older/RSA-configured roots — a small verifier dispatched on the metadata's declared
`method`. We register an **Ed25519** ECU key and sign the device manifest with `"ed25519"`.

### Key storage (MVP = "light", per decision)
- Device TLS cert/key, server CA, ECU signing key, and TUF root live in **encrypted NVS**; enable
  **flash encryption** on the dev boards.
- `aktualino_store` exposes a `key_provider` interface so the **hardware-backed path** (ESP32-S3
  **Digital Signature peripheral**, eFuse-bound keys, **Secure Boot v2**) drops in at Phase 4
  without touching callers.
- **Tradeoff acknowledged:** Torizon `device.zip` provisioning (§6) delivers the device private key
  in the bundle (over the TLS-protected wire). Fine for the MVP; the deferred alternative is
  on-device keygen + CSR so the private key never leaves the chip.

### Known sharp edge (re-provisioning)
A board that was **previously registered elsewhere** keeps an old TUF root (higher version,
different keys) and then **rejects new metadata** ("A key has an incorrect associated key ID").
`aktualino_store` must therefore support a clean **"reset TUF metadata, keep device identity"**
operation, and re-provisioning must trigger it.

---

## 9. Secure time
Uptane expiry checks are meaningless without trustworthy time. MVP: **SNTP** at boot, sanity-bounded
(reject absurd values), and treat metadata `expires` as a hard gate. `ASSUMPTION (confirm)`: no RTC
on the boards → we depend on network time each boot; note this limitation (a roll-forward-only clock
would be a hardening item).

---

## 10. ESP-IDF integration

- **Partition table** (custom): `nvs`, `otadata`, `phy_init`, **`ota_0`**, **`ota_1`** (+ optional
  tiny `factory`/recovery). App slot sizing:
  - Classic ESP32 (4 MB): ~1.8 MB per app slot — comfortable.
  - ESP32-S3 (8 MB): even more headroom.
- **A/B + rollback**: `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`, `esp_ota_mark_app_valid_cancel_rollback`.
- **Anti-rollback**: `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` + `esp_app_desc.secure_version`, wired to
  Uptane version so a downgrade target is refused both by us and by the bootloader.
- **mTLS**: esp-tls `clientcert_pem` / `clientkey_pem` / `cacert_pem` — native, proven on classic
  ESP32 by the ESP-IDF `esp_https_ota` examples.

---

## 11. Resource budget (rough, to be measured)

| Item | Est. RAM | Notes |
|---|---|---|
| TLS session (mbedTLS) | ~30–50 KB heap | tunable (fragment len, buffer sizes) |
| libsodium verify/sign | < 5 KB | Ed25519 is tiny |
| Metadata JSON buffers | few KB–tens KB | single-ECU Director targets are small; stream, don't hoard |
| OTA write | ~4 KB scratch | writes straight to flash |

Classic ESP32 WROVER (PSRAM) and S3 (8 MB PSRAM) both have ample margin. `ASSUMPTION (confirm)`: the
connected WROVER is an **ESP32-WROVER (4 MB flash + PSRAM)** — verify actual module/flash at Phase 0.

---

## 12. Phased roadmap

| Phase | Deliverable | Exit criteria | Backend needed |
|---|---|---|---|
| **0 — Foundations** ✅ **DONE** | ESP-IDF skeleton: WiFi, SNTP, A/B partition table, `esp_https_ota` against a dumb TLS server; prove rollback | An unsigned `.bin` served over HTTPS installs into the inactive slot, boots, confirms, and rolls back on a forced failure — **proven** (`stageA/B/C-*.log`) | none (local server) |
| **1 — Provisioning** ✅ **DONE** | `aktualino_prov` + `aktualino_store`: fetch `device.zip`, store creds, mTLS to gateway, ECU register | ESP appears as a device in the Torizon Cloud console; manifest **ACCEPTED** (`torizon-provision.log`) | Torizon Cloud |
| **2 — Director verify** ✅ **DONE** | `aktualino_uptane` + `aktualino_crypto`: canonical JSON, root/targets verify, expiry, rollback, target select | Device only accepts correctly-signed, in-date, non-downgrade Director assignments; **proven live** against Torizon RSA keys | Torizon Cloud |
| **3 — Update loop** ✅ **DONE** | `aktualino_ota` end-to-end: download → hash/verify → A/B flash → reboot → confirm/rollback → signed manifest | Deployed v0.1.0→v0.2.0 from the cloud; device updated, reported **success**; corrupt/rollback refused | Torizon Cloud |
| **4a — Two-repo Uptane** ✅ **DONE** | Image-repo verification + `ts→snap→targets` meta-hash chain + mandatory cross-repo target match | Installs **only** when Director AND Image repo sign the identical target; Director-only/mismatch refused (host 7/7) | Torizon Cloud |
| **4b — Hardening** ⏳ deferred | Secure Boot v2, flash encryption, S3 DS peripheral key path, on-device keygen+CSR | keys hardware-bound | — |

> Roadmap note (as-built): the original **Phase 4** bundled Image-repo verification with the
> irreversible hardening and the Torizon Cloud validation. As built, the Image-repo / two-repo
> Uptane work landed as **Phase 4a** (DONE) and the **Torizon Cloud validation is complete**
> (`docs/torizon-cloud-validation.md`); only the eFuse-burning hardening is split out as **4b**
> (deferred — `docs/hardening-todo.md`, maintainer-supervised).

---

## 13. Open questions / assumptions — resolved

Wire protocol, key types, ECU registration, and manifest signing are **pinned** (Appendix A) and the
earlier unknowns are resolved as built against Torizon Cloud:

1. **Provisioning** — Torizon Cloud device registration (`POST /accounts/devices` → `device.zip`);
   trust-anchor roots from `credentials.zip`. Confirmed on hardware.
2. **ECU-serial format** — alphabetic, length 10–64 (`ValidEcuIdentifier`); the device uses
   `"aktualinoesp" + MAC/nonce → a..p`. Accepted by the Director.
3. **Target storage mode** — Torizon serves a binary target as **HTTP 302 → presigned S3**; the
   downloader follows the redirect (§7.4).
4. **Signature primitive** — Torizon signs every role **RSASSA-PSS-SHA256 / RSA-2048**; the device's
   own ECU manifest is Ed25519. Both handled by the verify core.

---

## 14. Proposed repo layout
```
aktualino/
  SPEC.md                    ← this document
  README.md
  CMakeLists.txt             ← ESP-IDF top-level
  sdkconfig.defaults         ← rollback/anti-rollback, flash-enc, PSRAM, mbedTLS tuning
  partitions.csv             ← nvs/otadata/ota_0/ota_1
  main/
  components/                ← the modules in §5
  test/                      ← host-side unit tests (canonical JSON, verify) + on-target smoke
  tools/                     ← dev scripts: build/sync, NVS provisioning injector, capture
```

---

## 15. What Aktualino is *not* claiming
This is a research/demo client. Until Phase 4, it does **not** implement full two-repo Uptane, so it
should not be described as Uptane-compliant in the strong sense before then. The staging is explicit
precisely so we never accidentally overclaim the security posture at a given phase.

> **As-built update:** full two-repo Uptane verification (Director + Image repo, all four roles,
> meta-hash chain, mandatory cross-repo target match) **is delivered and hardware-proven** (Phase 4a),
> and **validated end-to-end against real Torizon Cloud** (`docs/torizon-cloud-validation.md`). It
> remains a research/demo client: keys are not yet hardware-bound (no Secure Boot / flash encryption /
> eFuse anti-rollback), and provisioning delivers the TLS key in `device.zip` rather than via an
> on-device CSR — see `docs/hardening-todo.md`.

---

## Appendix A — Device wire protocol (pinned from vendored source)

Verified against the OTA-Connect device-gateway protocol (director + reposerver + libats
canonical-JSON) and against live Torizon Cloud responses.
The device speaks **mTLS to the gateway** (`https://dgw.torizon.io`); the gateway derives the device
UUID from the client-cert **CN**, injects `x-ats-namespace: default`, disables gzip, and rewrites
paths. The device sends **only its client cert** on these calls (no bearer, no namespace header).

### Endpoints (device-relative)
| Purpose | Method | Path | Proxies to |
|---|---|---|---|
| Director root (latest / versioned) | GET | `/director/root.json`, `/director/{N}.root.json` | director `…/device/{uuid}/…` |
| Director timestamp / snapshot / targets | GET | `/director/{timestamp,snapshot,targets}.json` | director |
| **ECU registration** | POST | `/director/ecus` | director |
| **Device manifest** | PUT | `/director/manifest` | director |
| Image-repo metadata | GET | `/repo/{root,timestamp,snapshot,targets}.json`, `/repo/{N}.root.json` | reposerver `…/user_repo/…` |
| **Target binary** | GET | `/repo/targets/<path…>` | reposerver — streamed `application/octet-stream` (S3 target → `302`) |

### Signed envelope (all metadata + manifest)
```
{"signatures":[{"keyid":<64-hex>,"method":"ed25519"|"rsassa-pss-sha256","sig":<base64>}],
 "signed":{…}}
```
Signature is computed/verified over the **canonical-JSON bytes of `signed`** only.

### Canonical JSON (reproduce byte-exact, else every verify fails)
Recursively: **sort object keys** ascending (lexicographic by UTF-16 code unit) at every level;
**preserve array order**; serialize **minified** (no whitespace) with standard JSON string escaping;
**numbers kept verbatim** as received; encode **UTF-8**.

### `POST /director/ecus` — body
```
{ "deviceId": <uuid?>,
  "primary_ecu_serial": <ecu_serial>,
  "ecus": [ { "ecu_serial": <ecu_serial>,
              "hardware_identifier": <hwid, 0–200 chars>,
              "clientKey": { "keytype":"ED25519", "keyval": { "public": <pubkey> } } } ] }
→ 201 Created (new) | 200 OK (update)
```

### `PUT /director/manifest` — `signed` (V3, current)
```
{ "primary_ecu_serial": <ecu_serial>,
  "ecu_version_manifests": {
    "<ecu_serial>": {                       // nested SignedPayload[EcuManifest], signed by the ECU key
       "signatures":[{keyid,method,sig}],
       "signed": {
          "installed_image": { "filepath": <TargetFilename>,
                               "fileinfo": { "hashes": { "sha256": <64-hex> }, "length": <int> } },
          "ecu_serial": <ecu_serial>,
          "attacks_detected": ""            // "" when none
       } } },
  "installation_report": null | { "content_type": <str>,
      "report": { "correlation_id":<str>, "result":{…}, "items":[…], "raw_report":<str?> } } }
```
Outer envelope signed by the **primary ECU key**; each nested manifest by **that ECU's key** (for a
single-ECU ESP, both signatures use the one on-device Ed25519 key). Hashes carry **sha256 only**.
V1/V2 shapes are still accepted server-side but Aktualino emits V3.

### Constraints
`hardware_identifier` 0–200 chars. `TargetFilename` non-empty, < 254 chars, no `..`. `ecu_serial`
exact predicate is in a non-vendored `libats` jar (tests imply ≤ 64 alphabetic — confirm on the
live instance). All metadata/manifest sig methods must be `ed25519` (default) or `rsassa-pss-sha256`.
