/*
 * aktualino_ota — ESP-IDF A/B OTA wrapper (SPEC §5, §7, §10).
 *
 * Wraps esp_ota_* so the update loop can: open the *inactive* slot, stream
 * bytes into it while hashing them (streaming SHA-256, never buffering a whole
 * image in RAM — SPEC §7.4), finalize, flip the boot slot, and — after the new
 * image reboots pending-verify — either confirm it valid or roll back.
 *
 * The streaming SHA-256 lets the caller compare the computed digest against the
 * Uptane target `sha256` (SPEC §7.5) using the exact bytes written to flash.
 *
 * Typical flow:
 *     aktualino_ota_ctx_t ota;
 *     aktualino_ota_begin(&ota, image_len_or_0);
 *     // for each downloaded chunk:
 *     aktualino_ota_write(&ota, buf, n);
 *     uint8_t sha[32];
 *     aktualino_ota_end(&ota, sha);          // finalize flash + hash
 *     // compare sha to target hash, then:
 *     aktualino_ota_set_boot(&ota);          // next reboot boots the new slot
 *     esp_restart();
 *     // ... new image boots pending-verify; after self-check:
 *     aktualino_ota_mark_valid();            // or aktualino_ota_rollback()
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "mbedtls/sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    esp_ota_handle_t handle;          /* esp_ota_begin handle */
    const esp_partition_t *partition; /* target (inactive) slot */
    mbedtls_sha256_context sha;        /* streaming SHA-256 over written bytes */
    size_t written;                    /* bytes written so far */
    bool active;                       /* an OTA session is open */
} aktualino_ota_ctx_t;

/*
 * Open an OTA session against the next-update (inactive) partition.
 * `image_size` may be OTA_SIZE_UNKNOWN (0) when the length is not yet known;
 * pass the target length when known so the driver can erase precisely.
 * Initializes the streaming SHA-256.
 */
esp_err_t aktualino_ota_begin(aktualino_ota_ctx_t *ctx, size_t image_size);

/* Write one downloaded chunk to flash and fold it into the running SHA-256. */
esp_err_t aktualino_ota_write(aktualino_ota_ctx_t *ctx,
                              const void *data, size_t len);

/*
 * Finalize: flush/validate the OTA write (esp_ota_end) and finish the hash.
 * On success writes the 32-byte digest to `out_sha256` (may be NULL to skip).
 * Does NOT change the boot partition — call aktualino_ota_set_boot() for that.
 */
esp_err_t aktualino_ota_end(aktualino_ota_ctx_t *ctx, uint8_t out_sha256[32]);

/* Make the just-written partition the boot target for the next reset. */
esp_err_t aktualino_ota_set_boot(aktualino_ota_ctx_t *ctx);

/* Abort an open session (frees the esp_ota handle + hash) without booting it. */
void aktualino_ota_abort(aktualino_ota_ctx_t *ctx);

/*
 * Confirm the currently-running (freshly-booted, pending-verify) image as good,
 * cancelling the pending rollback. Call once self-checks pass (SPEC §7.7).
 */
esp_err_t aktualino_ota_mark_valid(void);

/*
 * Mark the running image invalid and reboot into the previous slot. Does not
 * return on success. Use when the self-check fails (SPEC §7.7).
 */
esp_err_t aktualino_ota_rollback(void);

/*
 * Log the running partition (label, subtype, address) and its OTA state
 * (e.g. PENDING_VERIFY / VALID / ABORTED) for the boot banner (SPEC §5).
 * `out_pending_verify` (nullable) is set true when the running image still
 * needs confirmation.
 */
esp_err_t aktualino_ota_running_info(bool *out_pending_verify);

/*
 * True (via *out) when the inactive (next-update) slot is in a failed OTA state
 * (INVALID / ABORTED) — i.e. an image we installed there booted, failed its
 * self-check, and the bootloader rolled back to this running image (SPEC §7.7).
 * Lets the post-reboot path tell a rollback from a clean confirm.
 */
esp_err_t aktualino_ota_inactive_slot_failed(bool *out);

#ifdef __cplusplus
}
#endif
