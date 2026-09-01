# Writing & deploying Berry script bundles

Aktualino can run small **[Berry](https://github.com/berry-lang/berry) scripts** on the device that
you deploy over the air — read a pin, toggle a relay, small logic — **without recompiling or
reflashing the firmware**. A script is delivered as its own Uptane target (two-repo verified, exactly
like a firmware update) to a virtual "secondary ECU" with hardware id **`aktualino-lua`**, then run in
an embedded VM. Design details: [`berry-secondary-spec.md`](berry-secondary-spec.md).

This page is the practical guide: write a bundle → validate it on your laptop → publish + assign it.

> **Requires the feature to be built in.** The firmware must be built with
> `CONFIG_AKTUALINO_SCRIPT_SECONDARY=y` (see `sdkconfig.berry.esp32` / `sdkconfig.berry.esp32s3`). It
> is **off by default**. Board: an **ESP32-S3**, or a **classic ESP32 with PSRAM (WROVER)** — a bare
> WROOM (no PSRAM) is not supported yet.

## 1. What a bundle is

A single Berry source file (`.be`). It defines two optional entry points:

```berry
#- aktualino-bundle: what this does -#
var BUNDLE = { "schema": 1, "version": "1.0.0", "requires_host_api": 1 }

def setup()
  # runs once when the bundle becomes active
end

def loop()
  # runs repeatedly (~every 500 ms) while the bundle is installed
end
```

- `setup()` runs once when the bundle is (re)loaded — at install and on every boot.
- `loop()` is called by a background scheduler roughly every **500 ms**, forever, so your script keeps
  running. Do **not** block or sleep inside `loop()`; return quickly and use `millis()` to pace
  yourself (see `blink.be`).
- The `BUNDLE` table is metadata. `requires_host_api` is a compatibility gate: if it is greater than
  the firmware's host-API version, the firmware refuses the bundle.

## 2. Host API (what a script can call)

These are plain global functions, registered on every bundle's VM:

| Function | Effect |
|---|---|
| `gpio_mode(pin, mode)` | pin direction: `mode` 0 = input, 1 = output, 2 = input-pullup |
| `gpio_set(pin, level)` | drive a pin (forces output); `level` 0 or 1 |
| `gpio_get(pin)` | read a pin → 0/1 |
| `millis()` | milliseconds since boot (integer) |
| `report(name, value)` | record a named value (currently logged to serial) |
| `health_ok()` | signal the bundle started healthy |
| `log(msg)` | print a line to the serial log |

**Safety:** GPIO 6–11 (the SPI-flash pins) are refused — a script can't brick the board that way.
There is otherwise **no capability allowlist yet**, so a signed script can drive any other pin/bus.

**Not available yet** (planned): `adc_read`, I2C, timers, a persistent key/value store, PWM/SPI. See
the spec §7.

Three ready examples live in [`examples/bundles/`](../examples/bundles): `hello.be`, `blink.be`,
`button-led.be`.

## 3. Validate on your laptop (no board needed)

```bash
examples/run.sh examples/bundles/blink.be
```

This compiles the vendored Berry VM and runs your bundle through `setup()` + a few `loop()`s with stub
host functions, so you catch syntax/logic errors before publishing. Needs a C compiler + `python3`.

## 4. Publish + assign to a device

You need a Torizon Cloud **`credentials.zip`** (Torizon Cloud → *Settings → Repository → Download
Credentials*). Unpack the pieces Aktualino uses into a secrets dir (default `secrets/torizon/`, kept
out of git):

- `secrets/torizon/extracted/treehub.json` + `tufrepo.url` — from `credentials.zip` (publishes targets)
- `secrets/torizon/api-client.json` — a **Platform API v2** client `{token_endpoint, client_id, secret}`
  you create in the Torizon console (assigns updates)

Then, with `tools/aktualino-bundle.py`:

```bash
# one-shot: publish blink.be as aktualino-lua v1.1.0 and assign it to a device
tools/aktualino-bundle.py deploy examples/bundles/blink.be \
    --version 1.1.0 --device <your-device-uuid>

# or step by step
tools/aktualino-bundle.py publish examples/bundles/blink.be --version 1.1.0
tools/aktualino-bundle.py assign  --package aktualino-lua-1.1.0 --device <uuid>
tools/aktualino-bundle.py status  --device <uuid>            # watch it reach "Succeeded"
```

`--secrets <dir>` (or `$AKT_TORIZON_SECRETS`) points at your credential dir. Bump `--version` for each
new bundle — the device only installs a target it hasn't already got.

## 5. What happens on the device

The device (each Director poll) selects the `aktualino-lua` target, **two-repo cross-verifies** it
(Director + Image repo must sign the identical bytes), downloads it (following the object-storage
redirect), checks sha256 + length, **validates** it (compile + `setup()` + first `loop()`s without
error), stores it verbatim in the `scripts` partition, swaps it in as the live bundle, and **reports
back** so the Torizon update reaches *Succeeded*. A previously-good bundle keeps running until a new
one validates; a bundle that throws in `loop()` too many times is quarantined (its `loop()` stops, the
firmware and OTA keep running).

## 6. Current limitations (MVP)

- Host API is GPIO + `millis` + logging; `report()` logs (no cloud telemetry uplink yet).
- Storage is a single "current" slot (no rollback-to-previous / KV store yet).
- The install gate is "loads + runs briefly without error" — the `health_ok()` heartbeat is logged
  but not yet required, and there is no per-`loop()` CPU budget or capability allowlist.

These are the hardening items on the roadmap (spec §13, S4/S5).
