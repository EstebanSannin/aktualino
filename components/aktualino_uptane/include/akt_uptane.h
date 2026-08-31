/*
 * akt_uptane — PORTABLE Uptane role/manifest logic (host + ESP32 target).
 *
 * Depends only on portable libs (cJSON + akt_crypto). No ESP-only headers, so
 * the same logic compiles for host tests and both ESP targets. The esp_err_t
 * wrappers in aktualino_uptane.c adapt these to the ESP component API.
 *
 * Covers T1.3 (signed-envelope parse, role verify + threshold + expiry +
 * version monotonicity, Director target selection) and T1.4 (V3 device
 * manifest builder, double Ed25519 sign).
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#include "cJSON.h"
#include "akt_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AKT_OK              =  0,
    AKT_ERR_PARSE       = -1,   /* malformed JSON / envelope shape          */
    AKT_ERR_NO_ROLE     = -2,   /* role missing from root metadata          */
    AKT_ERR_THRESHOLD   = -3,   /* valid signature count < threshold        */
    AKT_ERR_EXPIRED     = -4,   /* signed.expires <= now                    */
    AKT_ERR_ROLLBACK    = -5,   /* signed.version < min_version             */
    AKT_ERR_NO_TARGET   = -6,   /* no target matched hardware id            */
    AKT_ERR_INTERNAL    = -7,   /* allocation / crypto failure              */
    AKT_ERR_CROSSREPO   = -8,   /* metadata-hash chain / cross-repo mismatch*/
} akt_err_t;

/* A selected Director target for our hardware id (SPEC §7.3). */
typedef struct {
    char    filepath[254];   /* TargetFilename: non-empty, <254, no ".."   */
    uint8_t sha256[32];      /* expected image hash                        */
    size_t  length;          /* expected image length in bytes             */
    long    version;         /* custom.version, for anti-rollback (0 if absent) */
} akt_target_t;

/*
 * A second ECU's version report, for the optional Berry script secondary
 * (docs/berry-secondary-spec.md §2). The secondary reuses the primary's Ed25519
 * key (its clientKey is registered identically), so the same (pk, sk) signs both
 * nested EcuManifests. `installed` is the currently-installed bundle image
 * (filepath/sha256/length); a device with no bundle yet reports the empty-image
 * placeholder — filepath "unknown", length 0, sha256 of the empty string.
 */
typedef struct {
    const char  *ecu_serial;        /* the secondary's ecu_serial (e.g. "…-lua") */
    akt_target_t installed;         /* installed bundle image (or empty placeholder) */
    const char  *attacks_detected;  /* "" or a cause (API-mismatch/quarantine/rollback) */
} akt_secondary_t;

/*
 * Verify a signed role envelope against trusted root metadata.
 *   root_signed : parsed `signed` object of root.json ({keys, roles, ...})
 *   role_name   : "root" | "targets" | "snapshot" | "timestamp"
 *   envelope    : parsed { "signatures":[...], "signed":{...} } for the role
 *   now         : current unix time for the expiry gate (0 to skip expiry)
 *   min_version : reject if signed.version < min_version (rollback protection)
 * Returns AKT_OK or a negative akt_err_t.
 */
int akt_verify_role(const cJSON *root_signed, const char *role_name,
                    const cJSON *envelope, time_t now, long min_version);

/* Convenience: verify_role over raw envelope + root bytes. */
int akt_verify_role_bytes(const char *root_signed_json, size_t root_len,
                          const char *role_name,
                          const char *envelope_json, size_t env_len,
                          time_t now, long min_version);

/*
 * From a verified Director targets `signed` object, select the target whose
 * custom matches `hwid` — via custom.hardwareIdentifier, custom.hardwareIds[],
 * or the live Director custom.ecuIdentifiers.<serial>.hardwareId shape.
 */
int akt_select_target(const cJSON *targets_signed, const char *hwid,
                      akt_target_t *out);

/*
 * Extract the current assignment's correlation id from the Director targets
 * `signed.custom.correlationId` (e.g. "urn:here-ota:mtu:<uuid>") into `out`.
 * Returns AKT_OK, or AKT_ERR_NO_TARGET when absent.
 */
int akt_targets_correlation_id(const cJSON *targets_signed,
                               char *out, size_t cap);

/* ------------------------------------------------------------------ *
 * Image-repo (user_repo) meta-hash chain + cross-repo target matching.
 *
 * The Image repo is byte-stable (unlike the Director, which regenerates its
 * timestamp/snapshot/targets per request), so the full TUF hash chain holds on
 * /repo paths: timestamp.meta["snapshot.json"] pins snapshot.json, and
 * snapshot.meta["targets.json"] (and "root.json") pins those files. VERIFIED
 * against live Torizon Cloud reposerver bytes: the sha256 + length are computed
 * over the RAW SERVED BYTES of the whole {signatures,signed} envelope (NOT a
 * re-canonicalization) — the OTA-Connect reposerver stores each role's exact
 * signed bytes. So the device must hash exactly the bytes it received on the wire.
 * ------------------------------------------------------------------ */

/*
 * Verify that a referrer role's `signed.meta[meta_key]` correctly pins a
 * referenced metadata file:
 *   sha256(file_bytes[file_len]) == meta[meta_key].hashes.sha256   AND
 *   meta[meta_key].length        == file_len                       AND
 *   meta[meta_key].version       == ref_version   (when ref_version >= 0).
 * `file_bytes` MUST be the raw served bytes of the referenced file (the full
 * envelope), not a re-serialization. Returns AKT_OK, AKT_ERR_PARSE (bad shape),
 * or AKT_ERR_CROSSREPO (hash / length / version disagreement).
 */
int akt_verify_meta_link(const cJSON *referrer_signed, const char *meta_key,
                         const uint8_t *file_bytes, size_t file_len,
                         long ref_version);

/*
 * THE UPTANE TWO-REPO GUARANTEE. Confirm the Director-selected target `dir` is
 * present and identically signed in the (already role-verified) Image-repo
 * targets `signed`: the same filepath key exists with hashes.sha256 == dir->sha256
 * and length == dir->length. Returns:
 *   AKT_OK           — both repos agree; install may proceed,
 *   AKT_ERR_NO_TARGET— the Image repo does not sign this target (Director-only),
 *   AKT_ERR_CROSSREPO— present but sha256/length differ (tampered/mismatched).
 * Any non-AKT_OK result MUST refuse the install.
 */
int akt_image_target_matches(const cJSON *image_targets_signed,
                             const akt_target_t *dir);

/* Parse an ISO-8601 UTC timestamp ("YYYY-MM-DDTHH:MM:SSZ") to unix time. */
int akt_parse_iso8601_utc(const char *s, time_t *out);

/*
 * Build a V3 device manifest envelope (SPEC §7.8, Appendix A), double-signing
 * with the on-device Ed25519 ECU key:
 *   - inner EcuManifest `signed` is signed and wrapped in a SignedPayload,
 *   - outer manifest `signed` (carrying ecu_version_manifests) is signed.
 * Both signatures use the one ECU key (single-ECU ESP). installation_report is
 * emitted as null. Returns a malloc'd JSON string (caller frees) or NULL.
 */
char *akt_build_manifest(const char *primary_ecu_serial,
                         const akt_target_t *installed,
                         const char *attacks_detected,
                         const uint8_t ecu_pk[32], const uint8_t ecu_sk[64],
                         size_t *out_len);

/*
 * As akt_build_manifest, but when `correlation_id` is non-NULL/non-empty the
 * outer manifest carries a V3 `installation_report` (content type
 * application/vnd.com.here.otac.installationReport.v1) whose report.correlation_id
 * is `correlation_id` and whose result reflects `success` — so the Director marks
 * the matching assignment completed. A NULL correlation_id emits
 * installation_report: null (heartbeat manifest).
 */
char *akt_build_manifest_report(const char *primary_ecu_serial,
                                const akt_target_t *installed,
                                const char *attacks_detected,
                                const char *correlation_id, bool success,
                                const uint8_t ecu_pk[32], const uint8_t ecu_sk[64],
                                size_t *out_len);

/*
 * As akt_build_manifest_report, but when `secondary` is non-NULL the manifest
 * carries a SECOND ecu_version_manifests entry (keyed by secondary->ecu_serial) —
 * a nested EcuManifest signed by the SAME ECU key (key reuse, spec §3). Passing
 * secondary=NULL reproduces the single-ECU manifest byte-for-byte, so the
 * existing builders delegate here. The installation_report, when emitted, still
 * scopes result.items to the primary ecu (a bundle install's own report shape is
 * pinned in S2/S4); a heartbeat manifest (correlation_id NULL) just reports both
 * ECUs' installed images.
 */
char *akt_build_manifest_ex(const char *primary_ecu_serial,
                            const akt_target_t *installed,
                            const char *attacks_detected,
                            const char *correlation_id, bool success,
                            const akt_secondary_t *secondary,
                            const uint8_t ecu_pk[32], const uint8_t ecu_sk[64],
                            size_t *out_len);

#ifdef __cplusplus
}
#endif
