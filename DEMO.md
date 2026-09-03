# Aktualino — Demo & Rebuild Runbook

A reproducible, top-to-bottom runbook: build the firmware, provision a board to
**Torizon Cloud**, publish a target, assign it, and watch the two-repo-verified
A/B update install and report back.

Placeholders: `<build-host>` (a Docker-capable machine reachable over SSH),
`<device-uuid>` (the device UUID from provisioning), `<hwid>` (your chosen
hardware id, e.g. `aktualino-esp32`).

---

## 0. Prerequisites

- **A build host** with Docker (the SSH user must run `docker` without sudo) and
  the `espressif/idf:release-v5.4` image. Configure `tools/sync-build.sh` with
  environment variables (defaults in the script header):
  ```bash
  export AKTUALINO_BUILD_HOST=<build-host>
  export AKTUALINO_BUILD_USER=<ssh-user>        # optional
  export AKTUALINO_SSH_KEY=~/.ssh/id_ed25519    # optional
  export AKTUALINO_SERIAL_PORT=/dev/ttyUSB0     # for flash/monitor
  ```
- **An ESP32** (classic ESP32 or ESP32-S3) attached to the build host at the
  serial port above. A container run as root with `--device=<port>` can
  flash/monitor it.
- **A Torizon Cloud `credentials.zip`** (Torizon Cloud → Settings → Repository →
  Download Credentials), and a **user-scoped Platform API v2 client** for
  assignment (see `docs/torizon-cloud-validation.md`).
- **`secrets/wifi.env`** (gitignored) with a network that has internet:
  ```
  WIFI_SSID=<your-wifi>
  WIFI_PASS=<your-password>
  ```

---

## 1. Build + flash the baseline firmware

```bash
# Build both targets (also generates main/wifi_credentials.h from secrets/wifi.env):
tools/sync-build.sh build

# Flash + monitor the board (container opens the serial tty as root):
tools/sync-build.sh monitor esp32
```

To demo an update you flash a **lower** version first (the version the demo
updates *from*). The app version comes from the `AKT_APP_VERSION` build env var —
for a `0.1.0 → 0.2.0` demo, build+flash `0.1.0` as the baseline, and publish
`0.2.0` in step 3.

```bash
# a versioned build into its own dir, on the build host, via the container:
ssh $AKTUALINO_BUILD_USER@$AKTUALINO_BUILD_HOST \
  "docker run --rm -e AKT_APP_VERSION=0.1.0 -v \$HOME/aktualino:/project -w /project \
   espressif/idf:release-v5.4 idf.py -B build-esp32-v010 set-target esp32 build"
# then flash build-esp32-v010 to the board.
```

---

## 2. Provision the board to Torizon Cloud

Register the device and inject its identity into NVS (Approach A — the board never
holds an account secret):

`--out` is required, and the NVS **image** (`.bin`) is written by ESP-IDF's
`nvs_partition_gen.py` — so run the tool where IDF is reachable. The simplest way,
consistent with the Docker build host in Step 0, is to run it **inside the same
`espressif/idf` container** (which sets `$IDF_PATH`):

```bash
docker run --rm -v "$PWD":/project -w /project espressif/idf:release-v5.4 \
  tools/aktualino-provision.py --torizon \
    --credentials credentials.zip --hwid <hwid> --out prov-out
# -> prov-out/torizon-nvs.bin   device.zip creds + the Torizon Director/Image RSA roots
#    prov-out/nvs.csv, prov-out/files/   the inputs it was generated from
# Flash torizon-nvs.bin to the `nvs` partition at offset 0x9000, alongside the firmware:
#    esptool.py -p <port> write_flash 0x9000 prov-out/torizon-nvs.bin
```

Run without a container and the tool auto-finds `nvs_partition_gen.py` via
`--idf-path`/`$IDF_PATH`. If neither is set it still writes `prov-out/nvs.csv` +
`prov-out/files/` and prints the exact `nvs_partition_gen.py generate …` command
to finish the `.bin` yourself.

Or use the on-device **SoftAP portal** (Path B / A2) — see `docs/provisioning.md`.

On first boot the device does Wi-Fi + SNTP → ECU register (`POST /director/ecus`)
→ first manifest (`PUT /director/manifest`) and appears in the Torizon Cloud
console. Note its **device UUID** (`<device-uuid>`) — you assign the update to it.

```
POST /accounts/devices → device.zip           (creds stored in NVS)
on-device Ed25519 ECU key, keyid <hex>
POST /director/ecus → HTTP 201
PUT  /director/manifest → HTTP 200 ACCEPTED
```

---

## 3. Publish a target (Image repo)

Compute the sha256 + length of the binary you're publishing, then upload it to the
reposerver `user_repo` as a BINARY target (garage-tools token from
`credentials.zip`):

```bash
sha256sum build-esp32-v020/aktualino.bin        # -> <SHA256>
stat -c %s build-esp32-v020/aktualino.bin        # -> <LENGTH>

curl -sS -X PUT \
  "https://api.torizon.io/repo/api/v1/user_repo/targets/<hwid>-0.2.0?name=<hwid>&version=0.2.0&hardwareIds=<hwid>&targetFormat=BINARY" \
  -H "Authorization: Bearer <garage-tools-token>" \
  --data-binary @build-esp32-v020/aktualino.bin        # -> 204
# user_repo/targets.json is online-RSA-signed with this target — the IMAGE repo now agrees.
```

---

## 4. Assign the update (Platform API v2)

The repo-scoped garage-tools token 403s on assignment; use a **user-scoped
Platform API v2 client** token:

```bash
curl -sS -X POST https://app.torizon.io/api/v2beta/updates \
  -H "Authorization: Bearer <platform-api-token>" -H 'Content-Type: application/json' \
  -d '{"packageIds":["<hwid>-0.2.0"],"devices":["<device-uuid>"]}'
# -> 201  {"affected":[{"deviceUuid":"<device-uuid>", …}],"notAffected":[]}
```

`devices` takes up to 50 device UUIDs directly — no fleet required. Poll status at
`GET https://app.torizon.io/api/v2beta/updates/devices/<device-uuid>`.

---

## 5. Watch the ESP update

On the next 30 s poll the monitored device runs the loop (mirrors
`test/evidence/torizon-update-complete.log`):

```
UPDATE ASSIGNED: <hwid>-0.2.0 (len=<LENGTH> sha256=<SHA256>)
Image repo VERIFIED: … meta-hash chain ts->snap->targets over raw served bytes PASS
CROSS-REPO MATCH PASS: … signed by BOTH the Director and the Image repo — install allowed
GET …/repo/targets/<hwid>-0.2.0 → 302 → presigned S3 → OTA write <LENGTH> B
install: VERIFIED sha256 + length OK → boot partition set to ota_1 → reboot
UPDATE BOOTED: now running 0.2.0 → running image marked valid; rollback cancelled
manifest ACCEPTED: HTTP 200 → UPDATE COMPLETE
```

Later polls log `assigned target already installed — up to date (idempotent, no
re-update)`. Confirm in Torizon Cloud (Platform API v2): the device shows
`deviceStatus: UpToDate` and the update `status Completed, deviceResult {resultCode:
OK, success: true}`.

---

## 6. Serial capture

`tools/sync-build.sh monitor` streams live but does not persist. For a clean,
reset-triggered capture into an evidence file, use the pyserial helper inside a
container with the tty attached (how the `test/evidence/*.log` captures were made —
one handle resets and reads, avoiding the download-mode trap):

```bash
ssh $AKTUALINO_BUILD_USER@$AKTUALINO_BUILD_HOST \
  "docker run --rm --device=$AKTUALINO_SERIAL_PORT -v \$HOME/aktualino:/project -w /project \
   python:3-slim sh -c 'pip -q install pyserial && \
   python tools/akt_capture.py $AKTUALINO_SERIAL_PORT /project/test/evidence/demo-capture.log 120'"
```

Args: `akt_capture.py <tty> <logpath> <seconds>`.
