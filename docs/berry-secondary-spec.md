# Aktualino — Berry script secondary (Uptane-signed on-device plugins)

> _Status: **v0.1 — design agreed; S0 in progress on branch `feat/berry-secondary`.** Built on the
> shipped firmware client (`SPEC.md`), reusing its two-repo Uptane verification + delivery machinery
> unchanged. Sections marked `VALIDATE` must be proven against the live backend before we depend on
> them._
>
> **S0 COMPLETE (hardware-proven).** Berry v1.1.0 vendored + embedding wrapper
> (`components/aktualino_berry`), host test suite green, ESP-IDF component behind
> `CONFIG_AKTUALINO_SCRIPT_SECONDARY` (default off), feature-on partition variants, and a Kconfig-gated
> on-target selftest. **Cross-built both targets on the m920x:** the classic 4 MB WROVER fits
> feature-on with 103 KB (7 %) free in its 1.5 MB slot; the S3 has 55 % free (§10, §12). **Flashed to
> the classic ESP32 (D0WD): the selftest runs `setup()`/`loop()` + host natives + the health_ok
> heartbeat on-target, ~4 KB VM heap, alongside the normal OTA client** (`test/evidence/s0-berry-hardware.log`).
> Next: S1 (dual-ECU identity).
>
> **Backend scope: Torizon Cloud only** (`app.torizon.io` / `dgw.torizon.io`) — the sole backend per
> CLAUDE.md rule #2; the shipped client already dropped the Actualis path.

Aktualino already is a full two-repo Uptane client that A/B-flashes firmware. This feature adds a
**second, independently-versioned update track**: small **Berry** scripts that add device behavior
(read a sensor, toggle a GPIO, small logic) **without recompiling or reflashing the firmware**.

The key idea — a direct shrink of the generic partial-verification **secondary** from aktualizr — is
that a **script bundle is its own Uptane secondary target**, delivered and two-repo-verified by the
*same pipeline already built*, but where **install = write the bundle to a data/LittleFS partition +
load it in an interpreter**, instead of flashing an A/B app slot. The script runtime is a **virtual
secondary ECU** with its own `hardware_id`/`ecu_serial`, reported in the device manifest.

This is not a new mechanism grafted onto Torizon — it is exactly how **Torizon itself** already
updates containers and external MCUs: via Uptane **secondaries** driven by an **action-handler
contract**. We implement that same contract in firmware, with the Berry runtime as the target.

---

## 1. Goals & non-goals

### Goals (MVP)
- Deliver a **Berry script bundle** to an ESP32-S3 as an **Uptane secondary target**, two-repo
  verified by the existing `aktualino_uptane` + `aktualino_crypto` path — no new trust code.
- **Install = verify + write the bundle verbatim** to a LittleFS `scripts` partition; **run it** in
  an embedded Berry VM as a virtual secondary ECU (`aktualino-lua`).
- Expose a **host API** to scripts covering the full closed loop: **digital GPIO, ADC + I2C sensors,
  timers + persistent bundle-scoped key/value state, and `report(name, value)`** back to the cloud.
- **Self-confirm** a freshly-installed bundle via an explicit `health_ok()` heartbeat, and **roll
  back** to the previous bundle if it fails — the script analogue of `esp_ota_mark_app_valid`.
- Report the secondary's **installed image** (bundle filepath + sha256 + length + version) in the
  device manifest, byte-exact against the assigned target.
- **Be entirely optional at build time** — a user builds the firmware with or without the Berry
  secondary via a single Kconfig switch, at **zero cost** (flash, RAM, behavior) when off (§1.1).

### 1.1 Build-time optional (Kconfig)

The whole feature is gated behind one menuconfig switch — **`CONFIG_AKTUALINO_SCRIPT_SECONDARY`**
(bool, **default `n`** so the stock firmware is byte-for-byte what ships today; a per-target overlay
can flip it on for the S3). When **off**, none of the Berry/script machinery is compiled or
registered; when **on**, everything in this document applies. The gate touches four places:

- **Components.** `aktualino_berry` and `aktualino_script` are only built when the switch is on
  (guarded in their `CMakeLists.txt` via the Kconfig symbol). Off ⇒ the VM and host API are not
  linked ⇒ **~0 KB** added to the app image.
- **Partition table.** The `scripts` LittleFS partition exists only in the feature-on table variant.
  Crucially, because `scripts` is carved from the **unallocated headroom above `ota_1`** (§10), the
  on/off variants share **identical `ota_0`/`ota_1` offsets** → a device can **OTA in both directions
  between a no-Berry and a Berry firmware** without breaking A/B (only a device that will actually
  hold bundles needs the partition present).
- **ECU registration.** Off ⇒ the device registers **only the primary ECU** and emits today's
  single-ECU manifest. On ⇒ it registers both ECUs (§3.1) and emits the two-entry manifest.
- **Manifest / host-API version.** Off ⇒ no secondary `installed_image`, no `HOST_API_VERSION`
  advertised.

**Post-provision toggle caveat (MVP):** decide the switch **before provisioning**. Flipping a device
that was provisioned *with* the secondary to a firmware *without* it leaves an `aktualino-lua` ECU
registered in the Director that no longer reports → the director will show it stale / may flag a
missing ECU manifest. Off→on after provisioning needs the secondary ECU to be registered
(a re-register call). Clean re-registration on toggle is a post-MVP nicety, not MVP (§14).

### Non-goals (MVP)
- **Capability allow-listing / least-privilege sandboxing.** MVP ships the full API unconditionally;
  a firmware-side pin/bus allowlist is a **post-MVP hardening item** (§11).
- Multiple independent script ECUs. **One bundle = one secondary ECU** (§2).
- Multi-file bundles / assets. MVP is a **single amalgamated `.be` file** (§5); archive bundles are a
  growth path.
- Event/callback programming model. MVP is **host-called `setup()` + `loop()`** (§6); event
  callbacks are later.
- Optimizing for the classic 4 MB ESP32. **S3 is the headroom/production target** (8 MB flash + PSRAM,
  bigger slots, room for archive bundles/bytecode). The **4 MB WROVER is still a viable test target**,
  though — see §10: the existing partition table already has 896 KB of unallocated flash for a
  `scripts` partition, and the dev board has PSRAM for the VM heap. The only classic-specific unknown
  is whether the Berry-enabled app still fits the 1.5 MB slot (measured in S0).
- PWM, SPI, raw WiFi sockets, deep-sleep in the host API (post-MVP).

---

## 2. Concept: a script bundle is a secondary ECU

| Uptane / firmware concept | Firmware ECU (shipped) | **Berry script secondary (this doc)** |
|---|---|---|
| ECU identity | primary `ecu_serial` + `hardware_id` | secondary `ecu_serial` + `hardware_id` = **`aktualino-lua`** |
| ECU signing key | on-device Ed25519 | **reuses the primary's Ed25519 key** (same `clientKey` registered for both ECUs — see §3) |
| Target | firmware `.bin` | **Berry bundle** (single `.be`) published as a Torizon **generic package** |
| Install medium | inactive OTA slot (A/B) | **LittleFS `scripts` partition** (verbatim bundle bytes) |
| "Confirm valid" | `esp_ota_mark_app_valid_cancel_rollback` | **`health_ok()` heartbeat** within a window |
| Rollback | bootloader reverts to other slot | revert to the **kept previous bundle** |
| Manifest entry | `installed_image` = `.bin` hash | `installed_image` = **bundle hash + version** |

**Why one bundle = one ECU (not one-ECU-per-script):** one target, one version, one manifest entry,
one rollback unit. It keeps the Director assignment and the manifest simple, and matches how Torizon
models a subsystem. Scripts that need to cooperate live *inside* one bundle.

---

## 3. Backend model — Torizon Cloud

Delivery reuses `aktualino_net` (mTLS to `dgw.torizon.io`) and the two-repo verification path with
**zero changes** — a target is a target. Only three things are new to the backend interaction:

**3.1 Dual-ECU registration.** At provisioning, the device registers **both** ECUs in one call
(this is the native aktualizr flow — the primary registers itself and its secondaries together):

```
POST /director/ecus
{ "primary_ecu_serial": "<primary-serial>",
  "ecus": [
    { "ecu_serial": "<primary-serial>", "hardware_identifier": "aktualino-esp32s3",
      "clientKey": { "keytype":"ED25519", "keyval": { "public": <pubkey> } } },
    { "ecu_serial": "<lua-serial>",     "hardware_identifier": "aktualino-lua",
      "clientKey": { "keytype":"ED25519", "keyval": { "public": <SAME pubkey> } } } ] }
```

The **same public key** is registered for both ECUs (key reuse, by decision). The Director keys
verification per `ecu_serial`, not globally, so both nested manifests — signed by the one on-device
Ed25519 key — verify. Both "ECUs" are the same physical chip, so this is honest, and it saves a
keygen + a stored key. `VALIDATE`: confirm Torizon's director accepts two ECUs sharing a `clientKey`
(no cross-ECU key-uniqueness constraint expected).

**3.2 Publishing a bundle.** The Berry bundle is a Torizon **generic package** published against the
secondary's hardware id, e.g. (CI, `treehub`/platform tooling):

```
torizon platform push --hardwareid aktualino-lua \
    --package-name <name> --package-version <ver> <bundle.be>
```

No OSTree, no container — a plain signed blob. Its sha256/length flow into the Image-repo and
Director targets metadata exactly like a firmware target.

**3.3 Assignment.** The cloud assigns the bundle target to the device's **`aktualino-lua`** ECU (via
the platform API / update campaign). The device's existing poll already fetches the Director
`targets.json`, which lists assignments per `ecu_serial`; we simply also match the secondary's
serial. `VALIDATE` (the one real unknown, §14): confirm the Torizon Cloud **console + platform API**
can assign a generic-package target to a **secondary** ecu_serial on a device, not only the primary.
Torizon already targets secondaries for containers, so the director supports it; what needs proving
is the assignment surface end-to-end.

---

## 4. The action-handler contract (implemented in firmware)

Torizon's secondaries run through an action handler exposing `get-firmware-info` / `install` /
`complete-install` (their Cortex-M example literally shells out to `avrdude`). The ESP32 has no shell,
so **we implement the same three actions natively in C**, in a new `aktualino_script` component,
targeting the Berry runtime instead of an external MCU:

| Action | Contract | Aktualino implementation |
|---|---|---|
| `get-firmware-info` | report the installed version for the manifest | read stored bundle `version` + sha256/length → the secondary's `installed_image` |
| `install` | install the delivered payload | verify sha256 == target; write bundle **verbatim** to `scripts/staging`; atomically promote to `scripts/current`, demoting the old `current` → `previous` |
| `complete-install` | finalize | (re)start the Berry VM on `current`; arm the heartbeat window (§8) |

This keeps us inside Torizon's native secondary abstraction rather than inventing a parallel one.

---

## 5. Bundle format & Uptane identity

**Format (MVP): a single amalgamated Berry source file (`.be`).** Bytes-on-flash == target bytes ==
exactly what the VM loads — the tightest possible "what we sign is what runs."

**Leading metadata table** (parsed by the loader *before* execution, so it is inside the signed
bytes):

```berry
#- aktualino-bundle -#
var BUNDLE = {
  "schema": 1,
  "version": "1.4.0",          # human/semver, also the Uptane target custom version
  "requires_host_api": 3,      # refuse-to-load gate (§9)
  "entry": "setup",            # optional; defaults to setup()/loop()
  # "caps": [...]              # DECLARED intent only in MVP (no enforcement, §11)
}
```

**Uptane identity — how "what runs" == "what the cloud knows" (the core invariant).**
Uptane requires the ECU to report the identity of its **installed image**, matching the assigned
target — *not* the bytes the CPU executes at any instant (the firmware ECU reports the whole `.bin`
hash though it only ever runs a few instructions of it). So:

- We **store the exact received bundle bytes verbatim**; `sha256(scripts/current) == assigned target
  sha256` always holds and is re-checkable at any time (attestation on demand).
- The secondary's manifest `installed_image` = `{ filepath, hashes.sha256, length }` of the **whole
  bundle** + a `version` custom field — byte-exact against the Director's assignment.
- "What's running is only part of it" does not arise: the ECU installed *the bundle*; which functions
  inside it execute is the runtime's internal business, invisible to Uptane.

Berry can also load **precompiled bytecode**; if a future bundle ships bytecode, "what runs" == the
bytecode bytes == the target bytes — even more literal, but VM-version-locked (reinforces the §9
`requires_host_api` / VM-version contract). MVP ships **source**, which is more forgiving.

---

## 6. On-device architecture

```
components/
  aktualino_script/    NEW — the secondary: action-handler (§4), bundle store, loader, scheduler,
                       heartbeat/quarantine, host API bindings
  aktualino_berry/     NEW — vendored Berry VM (C99), thin init/teardown + allocator-in-PSRAM glue
  (reuses) aktualino_uptane / _crypto / _net / _store / _core   — verification + delivery unchanged
```

- **Dedicated FreeRTOS task**, lower priority than the OTA/core task, so a busy script never starves
  provisioning/polling/TLS. Its own stack (internal SRAM, small); the **Berry VM heap lives in PSRAM**
  (via a custom Berry allocator), so scripts never compete with the mbedTLS/OTA working set. Both the
  S3 and the WROVER dev board have PSRAM (§10, §12).
- **Scheduler = host-called entrypoints.** `setup()` once after (re)load; `loop()` on a tick. No
  script-owned blocking loop, so a missing yield can't wedge the system.
- **Per-`loop()` CPU budget** via Berry's instruction-count hook: a `loop()` that exceeds the budget
  is aborted for that tick (counts as a fault, §8). Bounds worst-case latency deterministically.
- **Timers** are host-managed: the scheduler dispatches script timer callbacks from the same task, so
  all Berry execution is single-threaded and needs no locking against itself.

---

## 7. Host API surface (MVP)

Full API, **no allowlist** (MVP decision). Exposed as Berry modules/functions (names indicative):

| Area | API (indicative) | Notes |
|---|---|---|
| Digital GPIO | `gpio.set(pin, level)`, `gpio.get(pin) -> level`, `gpio.mode(pin, IN/OUT)` | the "toggle a relay/LED" capability |
| Analog | `adc.read(channel) -> raw`, optional `adc.millivolts(channel)` | "read a sensor" (analog) |
| I2C | `i2c.write(addr, bytes)`, `i2c.read(addr, n) -> bytes`, `i2c.wreg/rreg` helpers | "read a sensor" (digital bus); a couple of built-in drivers can layer on later |
| Timers / sched | `timer.after(ms, fn)`, `timer.every(ms, fn)`, `timer.cancel(h)` | host-dispatched; no busy-wait |
| Persistent KV | `store.get(key[,default])`, `store.set(key, val)`, `store.del(key)` | bundle-scoped, survives reboot; backed by the `scripts` partition (§10) |
| Report | `report(name, value)` | pushes a named value into the manifest/telemetry channel (§8) — closes the sensor→cloud loop |
| Lifecycle | `health_ok()`, `log(level, msg)` | `health_ok()` is the confirm gate (§8) |

**Post-MVP:** PWM, SPI, raw sockets, deep-sleep, and the firmware-side capability allowlist that
makes `caps` enforceable rather than advisory.

---

## 8. Health, rollback & fault handling

**Confirm gate (install-time).** After `complete-install`, the new bundle is **pending**. It becomes
**confirmed** iff, within the heartbeat window, it: compiles/loads, runs `setup()` without error,
survives the first N `loop()` cycles without error, **and** calls `health_ok()`.
- Defaults: window **~30 s** / first **~10 `loop()`s**, `health_ok()` required at least once.
- On confirm → persist "confirmed", emit **success** for the secondary in the manifest.
- On failure (load/compile error, `setup()` throw, repeated `loop()` throws, VM OOM, CPU-budget
  overruns, or no `health_ok()` in window) → **revert to `scripts/previous`**, mark the new bundle
  **failed**, report failure via `installation_report` + `attacks_detected`-style signal.
- **Keep-last-good** always: `previous` is retained so revert is local and instant. First-ever bundle
  that fails → fall back to **no active script** (firmware keeps updating/polling normally).

**Post-confirmation faults (quarantine in place).** A bundle that already confirmed but later starts
throwing in `loop()` is *not* silently reverted (it was already reported good; a silent revert would
surprise the operator). Instead, after **3 consecutive `loop()` faults**, the scheduler **stops
calling `loop()`** (quarantine), keeps the bundle installed, and flags the fault in the manifest.
Firmware and OTA keep running; the cloud can push a fix or an explicit rollback target.

`report(...)` values and health/fault state ride the **existing manifest/telemetry channel** — no new
uplink path; the secondary's `installed_image` + a small custom status block carry it.

---

## 9. Versioning & the host-API contract

- **Bundle version monotonicity.** The bundle carries a version (target custom field, §5). We enforce
  monotonicity in **software** (store last-good version; refuse a lower one as defense-in-depth — the
  Director shouldn't assign a downgrade). No eFuse anti-rollback for scripts (that is firmware-only).
- **Host-API compatibility gate.** The firmware (which contains the interpreter + host API) updates
  on its **own A/B track**, independently of the script bundle. So a bundle can arrive expecting host
  functions an older firmware lacks, or vice-versa. Uptane does **not** model inter-target
  dependencies, so this gate is **ours**: the firmware exposes an integer `HOST_API_VERSION`; a bundle
  declares `requires_host_api`. If `requires_host_api > HOST_API_VERSION`, the firmware **refuses to
  load** the bundle and **reports the mismatch** (treated like a failed install → keep-last-good).
  Berry's small, deliberate API surface keeps `HOST_API_VERSION` stable and this contract cheap.

---

## 10. Partition layout

Add one LittleFS `scripts` data partition (**feature-on table variant only**, §1.1). **No change to
the OTA slots on either board** — both partition tables already carry enough unallocated headroom
above `ota_1`, so the feature-on and feature-off tables share identical `ota_0`/`ota_1` offsets and
stay mutually OTA-compatible.

**ESP32-S3 (8 MB flash, `partitions.esp32s3.csv`).** `ota_1` ends at `0x620000`, leaving ~1.9 MB
unallocated under 8 MB. Proposed `scripts` = **~512 KB** (generous; room for archive bundles later).

**Classic 4 MB WROVER (`partitions.csv`).** `ota_0`/`ota_1` are **1.5 MB each** (`0x180000`); `ota_1`
ends at `0x320000`, leaving **896 KB** (`0xE0000`) unallocated under 4 MB. Proposed `scripts` =
**128–256 KB** carved from that headroom — bundles are KB-scale, so this holds `current` + `previous`
+ `staging` + the KV store comfortably, with the OTA slots untouched.

| Partition | S3 | Classic 4 MB | Contents |
|---|---|---|---|
| `nvs`, `otadata`, `phy_init` | (existing) | (existing) | unchanged |
| `ota_0`, `ota_1` | ~3 MB each | ~1.5 MB each | firmware A/B (now also carries the Berry VM + host API) |
| **`scripts`** (LittleFS) | **~512 KB** | **~128–256 KB** | `current` (verbatim bundle), `previous` (rollback), `staging` (download), `kv/` (persistent store), `state` (pending/confirmed/quarantine + versions) |

The Berry VM and host API are **firmware** — they live in the shared app image (both OTA slots), not
in `scripts`. **Measured (S0, idf v5.4):** the full Berry runtime + wrapper + selftest grows the app
by **~133 KB** (more than the VM core alone — it includes Berry's string/json/math/time modules +
const tables). On the S3's 3 MB slot that is trivial (55 % free). On the classic's **1.5 MB** slot the
feature-on app is **1.40 MB → 103 KB (7 %) free** (vs 1.27 MB / 237 KB free feature-off) — so it
**fits with margin.**

---

## 11. Security model

**What Uptane guarantees here:** authenticity + integrity + freshness + anti-rollback of the *bundle*,
via the same two-repo (Director + Image repo) verification the firmware already passes. A bundle only
runs if correctly signed, in-date, non-downgrade, and cross-repo-matched — and only if
`sha256(installed) == assigned target`.

**What it does not guarantee (MVP caveats, stated so we never overclaim):**
- **No least-privilege sandbox.** Full API, always on. A *buggy* signed script can drive any exposed
  pin/bus. Fault-containment is via the VM (PSRAM-isolated heap, CPU budget, quarantine), **not** via
  capability restriction. The **post-MVP** firmware-side allowlist (device config pins which
  GPIOs/buses/addresses are scriptable; `caps` become enforced not advisory) is the hardening path.
- **Key reuse.** The secondary reuses the primary's Ed25519 key (§3). Acceptable — same physical
  chip — but not the "distinct key per ECU" a multi-chip vehicle would use.
- **Flash-at-rest.** The `scripts` partition and KV store are plaintext in MVP; flash encryption is a
  hardening item (shared with the firmware `docs/hardening-todo.md`, "requires Stefano present" —
  eFuse-burning is never enabled unattended, CLAUDE.md rule #4).

**Threat framing:** because bundles are Uptane-signed, the author is *authenticated*; the residual
MVP risk is a *buggy* (not hostile) script harming the device or starving the OTA client — which the
runtime bounds (task priority, PSRAM heap, CPU budget, heartbeat, quarantine) even without an
allowlist.

---

## 12. Resource budget (rough, to measure)

| Item | Est. | Notes |
|---|---|---|
| Berry runtime (flash) | **~133 KB measured** | full runtime + wrapper + selftest; in the shared app image. Classic feature-on app 1.40 MB / 1.5 MB slot → 103 KB (7 %) free; S3 1.35 MB / 3 MB → 55 % free (S0) |
| Berry idle RAM | ~10 KB, in **PSRAM** | grows with script; PSRAM keeps it off the TLS/OTA SRAM path — both S3 and WROVER have PSRAM |
| Bundle on flash | KB-scale | ×2 (current+previous) + staging, inside `scripts` (~512 KB S3 / ~128–256 KB classic) |
| Scheduler task stack | few KB SRAM | lower priority than core/OTA |

Feasibility is a green light on the S3 **and** on the 4 MB WROVER — Tasmota already runs Berry on 4 MB
ESP32s as its mainstream target. The constraint was never flash/RAM, it was the semantics above; the
only board-specific number left is the classic app-slot fit (S0).

---

## 13. Phased plan (SPEC-first, commit-per-unit, no push without go)

| Phase | Deliverable | Exit criteria |
|---|---|---|
| **S0 — Berry spike + partition** | `CONFIG_AKTUALINO_SCRIPT_SECONDARY` Kconfig gate (§1.1) + feature-on/off partition variants; vendored Berry builds for host + esp32s3 **+ esp32 (classic)**; `scripts` LittleFS partition; run a hard-coded `.be` with `setup()/loop()` and PSRAM heap | Feature **off** ⇒ image byte-identical to today (~0 KB delta); feature **on** ⇒ a trivial script toggles a GPIO on the S3 **and** the classic WROVER; host unit test runs Berry; **app+Berry binary size measured on both targets — classic fits the 1.5 MB slot** |
| **S1 — Secondary identity** | Dual-ECU registration (§3.1); secondary appears; dual-ECU manifest with a stub `installed_image` for `aktualino-lua` | Device shows both ECUs on Torizon Cloud; manifest ACCEPTED |
| **S2 — Delivery + install** | Publish a bundle as a generic package (§3.2); poll/assign for the secondary serial; action-handler `install` (verify sha + verbatim store + promote) | A cloud-assigned bundle is verified, stored, and its exact sha256 reported as installed |
| **S3 — Runtime + host API** | `aktualino_script` scheduler; full MVP host API (§7); `report()` into the manifest | A deployed script reads a sensor and reports a value to the cloud; updating the bundle changes behavior with no reflash |
| **S4 — Health & rollback** | Heartbeat confirm gate; keep-last-good revert; quarantine; `requires_host_api` gate (§8–9) | A bad bundle rolls back and reports failure; a post-confirm fault quarantines; an API-mismatch bundle is refused + reported |
| **S5 — Hardening** | Capability allowlist; flash encryption for `scripts`; bytecode-bundle option; Torizon Cloud campaign validation at scale | Same loop passes with allowlist on and `scripts` encrypted; validated via a Torizon Cloud update campaign |

---

## 14. Open questions / validation items

1. **`VALIDATE` (the one real unknown):** can Torizon Cloud's **console + platform API** *assign* a
   generic-package target to a **secondary** ecu_serial/hardware id on a device (not just the
   primary)? The director targets secondaries for containers, so the capability exists; prove the
   assignment surface end-to-end (publish `aktualino-lua` package → assign to device → device sees it
   in Director `targets.json` for the secondary serial). If assignment is primary-only in the product
   surface, fall back to the alternative model (one primary ECU, second target distinguished by
   custom metadata — noted, not chosen).
2. **`VALIDATE`:** director accepts two ECUs sharing one `clientKey` (§3.1).
3. Manifest shape for a **quarantined / API-refused** bundle — exact `installation_report` +
   `attacks_detected` fields Torizon's director accepts and surfaces (extend `SPEC.md` Appendix A).
4. Berry amalgamation ergonomics — do we ship one hand-written `.be`, or a tiny CI step that
   concatenates a small source tree into one signed `.be`? (Bundle format stays single-file either
   way.)
5. Exact `HOST_API_VERSION` surface to freeze for S3 (which functions are the stable v1 ABI).
6. Toggling `CONFIG_AKTUALINO_SCRIPT_SECONDARY` on a *provisioned* device (§1.1) — clean secondary-ECU
   re-registration on off→on, and de-registration/graceful-stale on on→off. Post-MVP; MVP fixes the
   switch before provisioning.

---

## Appendix A — extends `SPEC.md` Appendix A (device wire protocol)

Reuses the pinned Torizon device protocol; the only shape changes are **two ECUs** in
`POST /director/ecus` (§3.1) and **two entries** in the manifest `ecu_version_manifests` (primary +
`aktualino-lua`), each signed by the one on-device Ed25519 key. The secondary's nested `signed`:

```
{ "installed_image": { "filepath": "<bundle target path>",
                       "fileinfo": { "hashes": { "sha256": <64-hex> }, "length": <int> } },
  "ecu_serial": "<lua-serial>",
  "attacks_detected": "" }          # non-"" carries API-mismatch / quarantine / rollback cause
```

Bundle `version` and runtime status ride a custom block alongside `installed_image` (exact field
names pinned during S1/S4 against the live director).
