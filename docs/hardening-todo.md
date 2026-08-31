# Aktualino — Hardening & Deferred Work

The MVP (Phases 0–3 + 4a, full two-repo Uptane) is complete and hardware-proven. This document
lists the work deliberately **not** yet done, split into two groups:

1. **Irreversible (requires the maintainer present)** — steps that burn eFuses. These are **permanent**
   and can **brick a board** if mis-sequenced; the autonomous loop was explicitly forbidden from
   doing anything irreversible, so none of these are enabled today. Current firmware has **only**
   `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` on (burns nothing).
2. **Non-irreversible next features** — real code/UX work with no permanent hardware effect, but
   two of them need a phone/WiFi client (or a spare board) to test end-to-end, so they're best
   done with the maintainer around.

> **Do not enable any Group 1 item unattended.** Each fuses silicon. Prototype every one on a
> **sacrificial board** first, keep flash-encryption/Secure-Boot **keys backed up off-device**,
> and enable them in the right order (Secure Boot + flash encryption together, anti-rollback last).

---

## Group 1 — Irreversible (requires the maintainer present)

### 1.1 Secure Boot v2 (RSA-3072 / ECDSA signed bootloader + app)
- **What it buys:** the ROM only runs a bootloader signed by a key whose public-key digest is
  fused into eFuses; the bootloader in turn only runs a signed app. Combined with signed OTA
  images, an attacker with physical flash access cannot run modified firmware. This is the root
  of the on-device trust chain that the Uptane metadata verification sits on top of.
- **The risk:** **permanent.** Burning the public-key-digest eFuse and the "Secure Boot enable"
  bit is irreversible; a wrong key, a lost private key, or an unsigned image afterwards **bricks
  the board** (it will refuse to boot anything). JTAG and some ROM download-mode paths get
  disabled.
- **Enable steps (on a sacrificial board first):**
  1. Generate & **back up off-device** the signing key:
     `espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem`.
  2. `idf.py menuconfig` → Security features → *Enable hardware Secure Boot in bootloader*
     (`CONFIG_SECURE_BOOT=y`, `CONFIG_SECURE_BOOT_V2_ENABLED=y`), set the signing-key path.
  3. Build; the first flash over a wired connection burns the key digest + enable bit.
  4. Verify a signed app boots and an unsigned/wrong-key app is rejected, **before** doing this on
     any real unit. Keep the private key in the release signing store, never on the device.

### 1.2 Flash encryption (AES-256, eFuse key)
- **What it buys:** the app partitions, NVS (see 1.3), and bootloader are stored encrypted with a
  key held in eFuse and never readable by software; a physical flash dump yields ciphertext. Pairs
  with Secure Boot to protect confidentiality **and** integrity at rest — this is what makes the
  plaintext-NVS credential storage (device TLS key, ECU key, TUF metadata) actually safe.
- **The risk:** **permanent**, and the sharpest brick risk of all in **Release mode**: once in
  Release mode the UART download path can no longer re-flash plaintext, so a bad image is
  unrecoverable. Development mode allows a limited number of re-flashes; Release mode is one-way.
- **Enable steps (sacrificial board, wired power, do not interrupt the first encrypted boot):**
  1. Decide **Development** (debuggable, re-flashable a few times) vs **Release** (one-way) — start
     Development.
  2. `menuconfig` → Security features → *Enable flash encryption on boot*
     (`CONFIG_SECURE_FLASH_ENC_ENABLED=y`), select mode.
  3. First boot generates+burns the key and encrypts in place — **must not lose power** mid-encrypt.
  4. Only move a **known-good, fully-tested** build to Release mode, and only after 1.1 is proven.

### 1.3 NVS encryption (encrypted `nvs_keys` partition)
- **What it buys:** the device identity NVS (minted TLS cert+key, Ed25519 ECU signing key, pinned
  server CA, TUF metadata) is encrypted with keys in a dedicated `nvs_keys` partition. Today these
  live in **plaintext NVS** — this closes that gap. SPEC §8 always intended encrypted NVS; the MVP
  started plaintext by design.
- **The risk:** depends on 1.2 — the `nvs_keys` partition must itself be protected by flash
  encryption to be meaningful, so this inherits the permanence/brick risk of 1.2. Also requires a
  partition-table change (add an `nvs_keys` partition) — an OTA-incompatible layout change, so
  plan it as a factory re-flash, not an OTA.
- **Enable steps:** add `nvs_keys, data, nvs_keys, …, encrypted` to the partition table; build
  `aktualino_store` to open the NVS with `nvs_flash_secure_init` + the keys partition; enable flash
  encryption (1.2) so the keys partition is protected. Test read/write of every credential blob.

### 1.4 ESP32-S3 Digital Signature (DS) peripheral — eFuse-bound keys
- **What it buys:** the device's mTLS private key is wrapped by an eFuse-held key and used only via
  the DS peripheral — signing happens in hardware and the raw private key is never present in
  software or extractable. This is the hardware-backed `key_provider` path SPEC §8 designed for,
  and it removes the "key in NVS" exposure entirely. **S3 only** (the classic ESP32 has no DS
  peripheral).
- **The risk:** **permanent** (burns the HMAC/DS key eFuse); needs the ordered flow with flash
  encryption; requires an **ESP32-S3 to be physically connected** (currently it is not).
- **Enable steps:** provision via on-device keygen + CSR (2.1) so the key originates on-chip →
  wrap it for the DS peripheral (`esp_ds`) → burn the HMAC key → point esp-tls at the DS-backed
  key. Prototype on a spare S3 with flash encryption in Development mode first.

### 1.5 Anti-rollback eFuse `secure_version`
- **What it buys:** the bootloader refuses to boot an app whose `esp_app_desc.secure_version` is
  below the monotonic counter fused in eFuse — a hardware backstop under Aktualino's software
  rollback protection, so even a physically-downgraded image won't run. SPEC §10 wires this to the
  Uptane version.
- **The risk:** **permanent and monotonic** — each bump burns an eFuse bit; you can never boot an
  older `secure_version` again, so a buggy release that bumped the counter cannot be rolled back to
  its predecessor. Fuse bits are finite (budget your version cadence).
- **Enable steps:** `menuconfig` → *Enable app anti-rollback* (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y`),
  set `CONFIG_BOOTLOADER_APP_SECURE_VERSION`; bump `secure_version` **only** on releases that fix a
  security issue you must prevent downgrade to. Confirm the Uptane version→secure_version mapping so
  the device and the bootloader agree, and only bump after a build has proven itself in the field.

---

## Group 2 — Non-irreversible next features

### 2.1 On-device keygen + CSR provisioning (`/devices` flow)
- **What it buys:** with Torizon Cloud provisioning the device's TLS **private key is delivered in
  `device.zip`** (over TLS, but it originates off-device). The classic aktualizr `/devices` flow has
  the device **generate its own keypair on-chip** and send only a **CSR**; the private key never
  leaves the device. Prerequisite for the DS peripheral (1.4).
- **Why deferred / risk:** no permanent hardware effect — pure code + the backend endpoint. Needs
  the `/devices` CSR variant of Torizon Cloud's shared-provisioning `credentials.zip`; best validated
  with the maintainer so the backend side is confirmed.
- **Plan:** implement on-device EC P-256 keygen + PKCS#10 CSR in `aktualino_prov`; POST the CSR to
  the `/devices` endpoint; store the returned signed cert. Keep the `device.zip` injector as the
  fallback (SPEC §6.1 — one NVS schema, several injectors).

### 2.2 Provisioning UX hardening (SoftAP portal — built)
- **Status:** the SoftAP captive-portal wizard (`components/aktualino_portal`) and the host CLI
  injector (`tools/aktualino-provision.py`) are **built and hardware-validated** — a board
  self-provisions to Torizon Cloud from a phone browser. The remaining work is hardening, not
  greenfield.
- **What's left:** the setup AP is **OPEN** today (`TODO(security)` in the portal). Add **WPA2 + a
  per-device AP password + proof-of-possession** so an attacker in radio range can't drive the
  portal; consider session encryption for the pasted provisioning credential. A BLE provisioning
  transport is a later variant of the same framework.
- **Why deferred / risk:** no permanent hardware effect, but the security hardening is best
  validated with a phone/Wi-Fi client and the maintainer present.

### 2.3 Validation against Torizon Cloud (done)
- **Status:** **complete** — Aktualino is protocol-correct against real Torizon Cloud
  (`app.torizon.io`): provision, on-device RSA two-repo verify, publish, Platform API v2 assignment,
  mTLS+redirect download, A/B install, and a success manifest recorded Completed / OK. See
  `docs/torizon-cloud-validation.md` and `test/evidence/torizon-*.log`.
- **Next:** re-run against the `/devices` CSR provisioning variant once 2.1 lands.
