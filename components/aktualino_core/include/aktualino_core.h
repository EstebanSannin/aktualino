/*
 * aktualino_core — orchestrator: state machine, poll loop, config (SPEC §5).
 *
 * The full state machine (SPEC §5) is:
 *
 *   BOOT -> TIME_SYNC -> (PROVISIONED?) --no--> PROVISION --+
 *                              |yes                          |
 *                              v                             |
 *                        POLL_DIRECTOR <---------------------+
 *                              | assignment for our hw id?
 *              +----no---------+
 *              |               |yes
 *              |               v
 *              |   VERIFY_METADATA -> DOWNLOAD -> VERIFY_IMAGE ->
 *              |   INSTALL(inactive) -> REBOOT -> CONFIRM/ROLLBACK -> REPORT
 *              +--> REPORT_MANIFEST -> sleep(poll_interval) -> POLL_DIRECTOR
 *
 * Phase 0 exercises only the BOOT -> TIME_SYNC -> IDLE prefix; the remaining
 * states are declared here so later phases (T1.x+) fill them in without
 * reshaping the enum. This component owns state naming/transition logging; main
 * drives the transitions during bring-up.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"
#include "cJSON.h"   /* aktualino_core_verify_image_repo hands back a cJSON tree */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AKT_STATE_BOOT = 0,
    AKT_STATE_TIME_SYNC,
    AKT_STATE_PROVISION,
    AKT_STATE_POLL_DIRECTOR,
    AKT_STATE_VERIFY_METADATA,
    AKT_STATE_DOWNLOAD,
    AKT_STATE_VERIFY_IMAGE,
    AKT_STATE_INSTALL,
    AKT_STATE_REBOOT,
    AKT_STATE_CONFIRM,
    AKT_STATE_ROLLBACK,
    AKT_STATE_REPORT,
    AKT_STATE_IDLE,     /* Phase-0 terminal: booted, time-synced, waiting. */
    AKT_STATE_ERROR,
} aktualino_state_t;

/* Human-readable name for a state (for structured logging). Never NULL. */
const char *aktualino_state_name(aktualino_state_t st);

/*
 * Record a transition into `next` and log it as "state: <prev> -> <next>".
 * Returns the new state so callers can write `st = aktualino_transition(st, X)`.
 */
aktualino_state_t aktualino_transition(aktualino_state_t prev,
                                       aktualino_state_t next);

/* ------------------------------------------------------------------ *
 * Phase 2 — on-device Director metadata verification (SPEC §7.1–§7.3, §9).
 * ------------------------------------------------------------------ */

/* Outcome of one Director poll cycle. */
typedef struct {
    int32_t root_version;       /* trusted root version after the rotation walk */
    int32_t timestamp_version;  /* verified timestamp.json version               */
    int32_t snapshot_version;   /* verified snapshot.json version                */
    int32_t targets_version;    /* verified targets.json version                 */
    bool    target_assigned;    /* a target matched our hardware id              */
    char    target_path[254];   /* filepath of the assigned target (if any)      */
    size_t  target_length;      /* expected length of the assigned target        */
    char    target_sha256_hex[65]; /* expected sha256 (hex) of the assigned target */
    uint8_t target_sha256[32];  /* expected sha256 (raw bytes)                   */
    char    correlation_id[128];/* assignment correlation id (signed.custom)     */
} aktualino_poll_result_t;

/*
 * Establish the Director trust anchor (proper Uptane, TOFU-free). On first boot
 * the embedded root.json (shipped in firmware) is checked for self-consistency
 * (its own threshold of listed keys signed it) and persisted to NVS. On later
 * boots the persisted (possibly rotation-advanced) root is loaded. `now` is the
 * current unix time (0 to skip the embedded root's own expiry check at anchor
 * bootstrap). Must be called once after provisioning, before polling.
 */
esp_err_t aktualino_core_trust_anchor_init(const char *embedded_root_json,
                                           size_t len, int64_t now);

/* ------------------------------------------------------------------ *
 * Phase 4a — Image-repo (user_repo) trust anchor + two-repo verification.
 * ------------------------------------------------------------------ */

/*
 * Establish the IMAGE-repo (/repo, reposerver user_repo) trust anchor, exactly
 * like the Director one but a SECOND, independent anchor with its own keys and
 * its own NVS blob + version namespace. On first boot the embedded image
 * root.json is self-verified and pinned; later boots load the persisted root.
 */
esp_err_t aktualino_core_image_trust_anchor_init(const char *embedded_root_json,
                                                 size_t len, int64_t now);

/*
 * Verify the Image repo end-to-end and return its verified targets envelope
 * (caller cJSON_Delete's *out_targets_env): image root-rotation walk, then
 * timestamp/snapshot/targets (ed25519 threshold + expiry vs `now` + version
 * monotonicity), then the FULL meta-hash chain over the RAW served bytes
 * (timestamp pins snapshot.json, snapshot pins targets.json — sha256+length+
 * version). Returns ESP_OK only when every step passes.
 */
esp_err_t aktualino_core_verify_image_repo(int64_t now, cJSON **out_targets_env);

/*
 * THE UPTANE TWO-REPO GUARANTEE. Verify the Image repo (as above) and REQUIRE
 * that the Director-assigned target in `res` is signed identically
 * ({filepath, sha256, length}) in the Image-repo targets.json. Returns ESP_OK
 * only when BOTH repos agree; an error (and a loud ATTACK log) when the Image
 * repo does not sign the target or signs a different hash/length. Called
 * automatically by aktualino_core_download_and_install before any flash write.
 */
esp_err_t aktualino_core_crosscheck_target(const aktualino_poll_result_t *res,
                                           int64_t now);

/*
 * Run one full Director poll+verify cycle against the current trusted root:
 *   1. walk the root-rotation chain (/director/{N}.root.json) forward, each new
 *      root signed by the previous (threshold) and by itself; persist the latest,
 *   2. fetch + verify timestamp.json, snapshot.json, targets.json — canonical
 *      signature threshold, expiry vs `now` (hard-fail), version monotonicity vs
 *      NVS; persist the new versions,
 *   3. select any target assigned to `hwid`.
 * Fills `*out` (nullable). Returns ESP_OK when every role verified (whether or
 * not a target is assigned); an esp_err_t on the first verification failure.
 */
esp_err_t aktualino_core_poll_director(const char *hwid, int64_t now,
                                       aktualino_poll_result_t *out);

/* ------------------------------------------------------------------ *
 * Phase 3 — download + install (SPEC §7.4–§7.6).
 * ------------------------------------------------------------------ */

/*
 * True (via *is_new) when the poll's assigned target should be installed: it is
 * assigned AND its sha256 differs from the recorded running-image sha256
 * (Director-driven, avoids reflash loops). A device with no recorded running
 * image treats any assigned target as new.
 */
esp_err_t aktualino_core_target_is_new(const aktualino_poll_result_t *res,
                                       bool *is_new);

/*
 * Download the assigned target over mTLS (streaming GET
 * /repo/targets/<filepath>) straight into the inactive OTA slot while hashing,
 * verify sha256 == target hash AND length matches, then set the boot slot and
 * stage the pending-update record (filepath, sha256, length, correlation_id).
 * On ESP_OK the caller must reboot to activate the new image. On any failure it
 * aborts the OTA session cleanly and stays on the current slot (returns error).
 */
esp_err_t aktualino_core_download_and_install(const aktualino_poll_result_t *res,
                                              int64_t now);

#ifdef __cplusplus
}
#endif
