/*
 * aktualino_uptane — ESP component wrapper (esp_err_t surface) over the portable
 * akt_uptane core (akt_uptane.h). The real, host-unit-tested logic lives in the
 * portable core; this header is the on-target API (SPEC §5, §7, Appendix A).
 *
 * cJSON objects are passed as void* to keep the cJSON type out of this header,
 * matching the rest of the ESP component surface.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A selected Director target for our hardware id (SPEC §7.3). */
typedef struct {
    char    filepath[254];   /* TargetFilename: non-empty, <254, no ".." */
    uint8_t sha256[32];      /* expected image hash */
    size_t  length;          /* expected image length in bytes */
    int32_t version;         /* custom.version, for anti-rollback checks */
} aktualino_target_t;

/*
 * Serialize `cjson_obj` (a parsed cJSON object) into canonical JSON, writing at
 * most `cap` bytes to `out` and the true length to `*out_len` (SPEC Appendix A).
 * Returns ESP_ERR_INVALID_SIZE if the canonical form does not fit in `cap`.
 */
esp_err_t aktualino_uptane_canonical_json(const void *cjson_obj,
                                          char *out, size_t cap,
                                          size_t *out_len);

/*
 * Verify a signed role envelope against trusted root metadata.
 *   root_signed_cjson : parsed `signed` object of root.json  (cJSON*)
 *   role_name         : "root" | "targets" | "snapshot" | "timestamp"
 *   envelope_cjson    : parsed { signatures, signed } for the role (cJSON*)
 *   now               : unix time for the expiry gate (0 skips expiry)
 *   min_version       : reject if signed.version < min_version
 * Returns ESP_OK, or an esp_err_t mapping the akt_err_t failure reason.
 */
esp_err_t aktualino_uptane_verify_role(const void *root_signed_cjson,
                                       const char *role_name,
                                       const void *envelope_cjson,
                                       int64_t now, int32_t min_version);

/*
 * From a verified Director targets `signed` object (cJSON*), select the target
 * whose hardware_identifier matches `hwid`, filling `out` (SPEC §7.3).
 */
esp_err_t aktualino_uptane_select_target(const void *targets_signed_cjson,
                                         const char *hwid,
                                         aktualino_target_t *out);

/*
 * Build the V3 device manifest envelope (SPEC §7.8, Appendix A), double-signing
 * with the on-device Ed25519 ECU key (pk=32, sk=64). Writes the JSON to `out`
 * (<= cap) and its length to `*out_len`.
 */
esp_err_t aktualino_uptane_build_manifest(const char *primary_ecu_serial,
                                          const aktualino_target_t *installed,
                                          const char *attacks_detected,
                                          const uint8_t ecu_pk[32],
                                          const uint8_t ecu_sk[64],
                                          char *out, size_t cap,
                                          size_t *out_len);

#ifdef __cplusplus
}
#endif
