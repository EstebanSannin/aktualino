# Releasing Aktualino — CI, tested builds, and the web flasher

Aktualino ships **tested, no-secrets firmware** anyone can flash from a browser.
Two GitHub Actions workflows drive it; nothing here needs a secret, because the
public images carry none (a clean clone *is* the no-secrets "Path B" image — see
[`provisioning.md`](provisioning.md)).

## The two workflows

### `.github/workflows/ci.yml` — on every push / PR to `main`
1. **Host tests** (the gate): builds the portable Uptane core and runs the CTest
   suite (`tools/run-host-tests.sh`) — canonical JSON, Ed25519 + RSASSA-PSS
   verify, the meta-hash chain, and the two-repo cross-verify/refuse paths.
2. **Firmware build** — a 4-way matrix (`esp32`, `esp32s3`) × (`plain`, `berry`)
   in the pinned `espressif/idf:release-v5.4` image, from the clean checkout.
   This is what proves the tree still builds with **no generated inputs** (the
   thing the dead dumb-server CA embed used to break).

CI publishes the per-variant `aktualino.bin` as build artifacts for inspection;
it does **not** create a release.

### `.github/workflows/release.yml` — on a `v*` tag
1. **Host tests** — same gate; a release never ships if the core tests fail.
2. **Build + package** — the same 4-way matrix, with the app version set from the
   tag (`AKT_APP_VERSION`), then `esptool merge_bin` collapses
   bootloader + partition table + otadata + app into **one file flashable at
   `0x0`**: `aktualino-<target>-<variant>-<version>.bin`.
3. **GitHub Release** — attaches the four merged images + `SHA256SUMS` with
   generated notes.
4. **Deploy the web flasher** — assembles the ESP Web Tools page (`web/`) with the
   four images + generated manifests and publishes it to **GitHub Pages**.

## Cutting a release

The tag is the version — no file to bump:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The pipeline tests, builds all four variants at `0.2.0`, publishes the release,
and updates the flasher at `https://estebansannin.github.io/aktualino/`.

## One-time repo setup (a maintainer does this once)

- **Enable Pages from Actions:** repo **Settings → Pages → Build and deployment →
  Source: GitHub Actions**.
- **No secrets to configure.** The workflows use the automatic `GITHUB_TOKEN`;
  each grants only what it needs via a `permissions:` block (`contents: write`
  for the release, `pages: write` + `id-token: write` for the deploy). The built
  firmware carries no account credentials, so none are stored in CI.

## Flashing (what users get)

- **Web flasher (recommended):** `https://estebansannin.github.io/aktualino/` —
  plug in the board, click *Connect & install*. Works in desktop Chrome / Edge /
  Opera (WebSerial). ESP Web Tools auto-detects ESP32 vs ESP32-S3.
- **Command line:** download the merged image + `SHA256SUMS` from the release,
  verify, and (the merged image is flashed at offset 0):
  ```bash
  esptool.py --chip esp32 -p /dev/ttyUSB0 write_flash 0x0 aktualino-esp32-plain-0.2.0.bin
  ```
  (`--chip esp32s3` for the S3, and `-berry-` for the Berry variant.)

After flashing, the board opens its `aktualino-<mac6>` setup portal — see
[`provisioning.md`](provisioning.md).

## Supply-chain notes (this is an Uptane project — hold ourselves to it)

- **Images are secret-free by construction.** CI builds from a plain checkout;
  the release job never has provisioning credentials. Verified: a `git archive
  HEAD` tree (tracked files only) builds all four variants.
- **The flasher's CDN dependency is the weak link.** `web/index.html` loads ESP
  Web Tools from unpkg (major-version pinned). Hardening TODO (tracked in
  [`hardening-todo.md`](hardening-todo.md)): vendor it into the site with an exact
  pin + Subresource Integrity, or self-host, so the flasher trusts no third-party
  CDN at run time. Signing releases (minisign/cosign) is a natural next step too.
