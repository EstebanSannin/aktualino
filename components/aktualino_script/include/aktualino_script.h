/*
 * aktualino_script — the Berry script secondary (docs/berry-secondary-spec.md).
 *
 * The action-handler side of the second Uptane target track: on each Director
 * poll it selects the bundle target for hardware id "aktualino-lua", two-repo
 * cross-verifies it, downloads + sha/length-verifies it, stores it verbatim in
 * the `scripts` partition, runs it in the Berry VM, and reports the install back
 * to the Director (secondary-scoped installation_report with the target's
 * correlation id) so Torizon completes the update.
 *
 * The whole component is behind CONFIG_AKTUALINO_SCRIPT_SECONDARY.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Hardware id of the virtual secondary ECU. */
#define AKT_SCRIPT_HWID "aktualino-lua"

/*
 * Initialise the bundle store (locate the `scripts` partition). If a bundle is
 * already installed, load and run it once (setup() + a few loop() cycles) so a
 * reboot re-activates the current script. Safe to call when unprovisioned.
 */
esp_err_t aktualino_script_init(void);

/*
 * One secondary-track cycle, called from the main poll loop after the primary:
 *   - poll the Director for the aktualino-lua target (+ correlation id),
 *   - if none: no-op,
 *   - if assigned & new: two-repo cross-verify -> download -> sha/length verify
 *     -> run in Berry (load + setup() + first loop()s without error) -> store
 *     verbatim -> report installed (success/failure) with the correlation id,
 *   - if assigned & already installed: re-report success (idempotent) so a
 *     lingering "Seen" update completes.
 * `now` is unix time (for the two-repo expiry gate). Never fatal to the caller.
 */
esp_err_t aktualino_script_poll(int64_t now);

#ifdef __cplusplus
}
#endif
