# Provisioning Aktualino

How an ESP32 running Aktualino gets its **identity** (which device it is) and its
**Wi-Fi**. There are **two paths**; which one you use depends on *who flashes the board*. Torizon
Cloud is the backend.

> Status: the **CLI injector path** and the **SoftAP captive-portal** both work today. The portal
> (`components/aktualino_portal`) is hardware-validated: a curl-driven `POST /provision` self-
> provisioned an ESP32 to **Torizon Cloud** end-to-end via **Path A2** (baked `provision.json`),
> minting its own token, registering the device, and polling. See "On-device SoftAP portal" below.

## The question that decides the path
**Who flashes the board?** You (your own fleet) or someone who downloaded a prebuilt binary.

---

## Path A — Pre-provisioned (your own boards)
The provisioning credential is supplied **at flash time**; nothing secret is typed into the board.
The setup UI (if shown at all) only asks for **Wi-Fi**. Two flavors:

### A1 · Host pre-provision — per-device credentials (most secure; recommended for a fleet)
The host performs the device registration and flashes the resulting **per-device** identity into
NVS. The board carries only its own cert/key — **never** the account provisioning secret.
```
tools/aktualino-provision.py --torizon --credentials credentials.zip   # -> NVS image -> flash
```
This is exactly how Torizon Cloud was validated. Zero-touch if Wi-Fi is injected too; otherwise the
portal asks only for Wi-Fi.

### A2 · Baked provisioning client — self-provision (one image, many boards)
Bake your Torizon **provisioning client** (`provision.json` from `credentials.zip`) into the
firmware. Each board mints its own short-lived token and **self-registers** on first boot; the portal
asks only for **Wi-Fi (+ optional device name)**.
- **Tradeoff:** every board carries a secret that can register devices in your account → use **flash
  encryption** in production, and **never publish this binary**.

## Path B — Bring-your-own-credential (a downloaded binary)
The public `aktualino.bin` carries **no secrets**. Whoever sets up the board supplies **their own**
provisioning credential at setup, via the **captive portal** (paste) or the **CLI injector**. The
board then self-provisions like A2, but with the user's credential entered at runtime — a Torizon
Cloud provisioning token from *their* account (see below), **not** the 4-minute console token.

---

## Getting the credential — Torizon Cloud
`credentials.zip` (Torizon Cloud → Settings → Repository → Download Credentials) carries three
clients; keep them straight:

| File / client | Purpose | Where Aktualino uses it |
|---|---|---|
| `provision.json` (`provision_…`) | **device provisioning** (register devices → `device.zip`) | Path A2 (bake) · Path B (user provides) |
| `treehub.json` (`garage-tools_…`) | repo/tooling (sign & push targets) | publishing update targets (CI) |
| API V2 client (`tzn_api_…`) | Platform API (create + **assign** updates) | triggering updates (CI) |

- The console's **Provision Device → Torizon OS** dialog produces `curl … -t "<JWT>"`. That `-t`
  value is a **~4-minute OAuth access token** minted from `provision.json`. It *works* as a Bearer
  token to `POST https://app.torizon.io/api/accounts/devices` → `device.zip`, but its short life and
  ~800-char length make it a poor thing to type into a board. **Prefer the durable `provision.json`
  client.** A token minted directly from that client via the `client_credentials` grant can be
  longer-lived (the client's configured lifetime, up to ~7 days) — that's the credential to use for
  Path B, or bake the client itself for A2.
- Registration endpoint: `POST https://app.torizon.io/api/accounts/devices` (Bearer). Device
  gateway: `https://dgw.torizon.io`. Metadata is **RSA / RSASSA-PSS-SHA256**. Binary targets are
  served via a **302 → presigned S3 URL** (the client follows it).

---

## How it maps to the setup UI + CLI
- **SoftAP captive portal** (unprovisioned board with no Wi-Fi boots as an open AP
  `aktualino-<mac6>`, where `<mac6>` = the last 3 bytes of the factory MAC in hex):
  - **Path A** → collects **Wi-Fi only** (identity is already baked/injected).
  - **Path B** → collects **Wi-Fi + a provisioning credential**; the board self-provisions.
- **CLI injector** (`tools/aktualino-provision.py`) — writes the same NVS credential schema
  headlessly. First-class and shipped, for people who prefer a command over a portal.

## On-device SoftAP portal (`components/aktualino_portal`)

| Pick Wi-Fi | Board provisioned |
|:--:|:--:|
| ![setup portal — Wi-Fi selection](img/portal-wifi.png) | ![setup portal — provisioned](img/portal-done.png) |

Boot decision (`main/aktualino_main.c`): **provisioned** → poll loop; else **Wi-Fi creds known**
(NVS, written by the portal/CLI, else a build-time fallback) → connect + self-enrol; else → **start
the SoftAP portal**. On success the board reboots into the normal poll loop. A stubbed
factory-reset-to-AP hook (hold **BOOT/GPIO0**) clears identity + Wi-Fi + TUF and re-opens the portal.

- **SoftAP**: open AP, device-unique SSID `aktualino-<mac6>` (e.g. `aktualino-e40398`). AP is OPEN
  for now — there is a clear `TODO(security)` for WPA2 + a per-device password + proof-of-possession.
- **Captive page**: one embedded, gzipped, self-contained HTML page (system fonts, inline CSS/JS,
  **~7.0 KB compressed**) served by `esp_http_server`, plus a captive DNS responder (every A query →
  the AP IP) and a 404→portal redirect so phones auto-open the "Sign in to Wi-Fi" sheet.
- **Endpoints**: `GET /` (page), `GET /config` (backend + `credential_needed` → Path A/B + device
  readout), `GET /scan` (Wi-Fi scan JSON), `POST /provision` (`{ssid,password,credential?,
  device_name?}`), `GET /status` (`joining_wifi|sntp|requesting_creds|registering|verifying|done|
  error`). Path A vs B is decided by whether the board can self-provision without operator input:
  injected device creds (A1) or a baked Torizon client (A2) ⇒ `credential_needed:false`.
- **Submission limits**: each `POST /provision` field has a fixed on-device buffer — SSID 32,
  password 64, **credential 2047**, device name 47 characters. An overlong field is rejected with
  `400` + `{"ok":false,"error":"<field> too long (max N characters)"}` and the page shows that on the
  form; it is never truncated and provisioned with, which used to fail far downstream as an opaque
  `401` from the credential handshake. A real Torizon provisioning token is ~1.3 KB.

### Dev-only bench build (Path A2 → Torizon Cloud, hardware-proven)
`tools/sync-build.sh` generates `main/provision_client.h` from `secrets/torizon/extracted/`
(`provision.json` + the two public Torizon RSA roots). With it baked, the device self-provisions on
`POST /provision`: OAuth2 `client_credentials` at the `token_endpoint` → `POST
https://app.torizon.io/api/accounts/devices` → `device.zip` (inflated on-device with the ROM miniz)
→ store creds + seed the Torizon Director/Image roots → ECU register + first manifest. **This is
dev-only**: the header carries the account `client_secret`; it is `.gitignored`, never committed, and
needs **flash encryption** in production. Never publish a binary carrying it.

### Real phone test
Flash a board with the A2 demo image and leave it **unprovisioned in portal mode**. To run it:
1. On a phone, join the open Wi-Fi **`aktualino-<mac6>`** (the SSID is printed on the board's serial
   boot log). The captive "Sign in to Wi-Fi network" sheet opens the setup page automatically (or
   browse `http://192.168.4.1/`).
2. Pick the Wi-Fi the board should join and enter its password (no cloud credential is asked — the
   build is pre-configured for Torizon Cloud, `credential_needed:false`).
3. Tap **Provision device** and watch the steps: Joining Wi-Fi → Secure time → Requesting
   credentials → Registering ECU → Verifying → **Board provisioned** (shows the Torizon device UUID).
   The board then reboots and polls Torizon Cloud for signed updates on its own.

## Decision table
| You are… | Path | Setup asks for |
|---|---|---|
| Fleet, security-sensitive | **A1** host pre-provision | Wi-Fi only (or nothing) |
| One image for many of your boards | **A2** bake `provision.json` | Wi-Fi (+ name) |
| Shipping a public prebuilt binary | **B** bring-your-own | Wi-Fi + your provisioning credential |

## Flash cost (it's small)
The portal is one **embedded, minified (optionally gzipped) HTML page (~10–20 KB)** served by
ESP-IDF's `esp_http_server` (already in the SDK); the SoftAP + provisioning code adds **tens of KB**
of *shared* app code (not per-OTA-slot). Current classic-ESP32 builds leave **~360 KB free** in the
app slot, so this is comfortable. The page uses **system fonts** (the setup AP has no internet, so no
web-font download) and inlines its own CSS/JS — fully self-contained.
