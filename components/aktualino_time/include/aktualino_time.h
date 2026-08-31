/*
 * aktualino_time — secure(-ish) time for Uptane expiry checks (SPEC §9).
 *
 * Uptane metadata carries an `expires` field; verifying it is meaningless
 * without trustworthy wall-clock time. The boards have no RTC, so we depend on
 * SNTP each boot, sanity-bounded against an absolute floor to reject absurd
 * values. A roll-forward-only monotonic clock would be a later hardening item.
 *
 * Phase 0 scope: bring SNTP up and expose "is the clock plausibly correct?".
 */
#pragma once

#include <stdbool.h>
#include <time.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Any real (post-build) time must be at/after this floor. 2024-01-01 UTC.
 * Anything earlier means SNTP has not landed yet. */
#define AKTUALINO_TIME_FLOOR_EPOCH 1704067200

/*
 * Start SNTP (SMOOTH sync mode) against `server` (NULL => Kconfig default) and
 * block up to `timeout_ms` for the clock to cross AKTUALINO_TIME_FLOOR_EPOCH.
 *
 * Returns ESP_OK once time is valid, ESP_ERR_TIMEOUT if it did not sync in
 * time. Idempotent: safe to call again to re-arm.
 */
esp_err_t aktualino_time_sync(const char *server, uint32_t timeout_ms);

/* True once the wall clock is at/after the sanity floor. */
bool aktualino_time_is_valid(void);

/* Format the current UTC time as ISO-8601 into `buf` (>= 25 bytes). Returns buf. */
char *aktualino_time_iso8601(char *buf, size_t len);

#ifdef __cplusplus
}
#endif
