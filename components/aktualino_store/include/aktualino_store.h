/*
 * aktualino_store — persistence layer (SPEC §5, §6, §8).
 *
 * STATUS: Phase-0 compiling stub. Every function returns ESP_ERR_NOT_SUPPORTED
 * until Phase 1 (T1.5) implements it. The API is documented here so callers
 * (aktualino_prov, aktualino_core) can be written against a stable surface.
 *
 * Responsibilities (SPEC §5):
 *   - NVS-backed device identity: mTLS client cert/key (EC P-256, minted),
 *     server CA (pinned), gateway URL, device UUID, primary ECU serial, and the
 *     on-device Uptane ECU signing key (Ed25519).
 *   - TUF metadata store: the current root.json (and later timestamp/snapshot/
 *     targets) per repo, versioned for rollback protection (SPEC §7.2).
 *   - Install state: what version is installed / pending, correlation id for the
 *     next manifest.
 *
 * KNOWN SHARP EDGE (SPEC §8): a board previously registered elsewhere keeps an
 * old, higher-version TUF root and then rejects new metadata. aktualino_store
 * must therefore support "reset TUF metadata, keep device identity"
 * (aktualino_store_reset_tuf), invoked on re-provision.
 *
 * MVP starts on plaintext NVS; encrypted NVS (flash-encryption + NVS keys) is a
 * Phase-1/4 drop-in behind this same API (SPEC §8).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Device identity + gateway trust, as returned by POST /api/provision (SPEC §6)
 * plus the on-device Uptane key. PEM strings are NUL-terminated.
 *
 * On save (aktualino_store_save_creds) the caller owns these pointers. On load
 * (aktualino_store_load_creds) the store malloc()s each field; free the whole
 * struct with aktualino_store_free_creds(). */
typedef struct {
    const char *uuid;             /* device UUID (client-cert CN) */
    const char *gateway_url;      /* https://<host>:30443 */
    const char *client_cert_pem;  /* mTLS client cert (EC P-256) */
    const char *client_key_pem;   /* mTLS client private key */
    const char *cacert_pem;       /* pinned server CA */
    const char *ecu_serial;       /* primary ECU serial */
    /* Uptane ECU signing key (Ed25519) is stored/loaded via the key API below. */
} aktualino_creds_t;

/* Open/initialize the backing NVS namespaces. Safe to call more than once. */
esp_err_t aktualino_store_init(void);

/* True (via *out) when a full device identity is present in the store. */
esp_err_t aktualino_store_have_creds(bool *out);

/* Persist the device identity returned by provisioning (SPEC §6 step 3). */
esp_err_t aktualino_store_save_creds(const aktualino_creds_t *creds);

/* Load the device identity into a caller struct; every field is malloc()'d.
 * Free with aktualino_store_free_creds(). Returns ESP_ERR_NVS_NOT_FOUND if no
 * identity is stored. */
esp_err_t aktualino_store_load_creds(aktualino_creds_t *out);

/* Free the malloc()'d fields of a struct filled by aktualino_store_load_creds. */
void aktualino_store_free_creds(aktualino_creds_t *creds);

/* ------------------------------------------------------------------ *
 * Wi-Fi station credentials (SPEC §6.1: "WiFi creds live in the NVS blob,
 * never in firmware source"). Written by an injector — the SoftAP captive
 * portal (aktualino_portal), the host CLI, or a build-time header fallback —
 * and read by main's STA bring-up. Distinct from the OTA-backend identity
 * above: a board can have Wi-Fi creds without being provisioned yet.
 * ------------------------------------------------------------------ */

/* True (via *out) when a Wi-Fi SSID has been stored. */
esp_err_t aktualino_store_have_wifi(bool *out);
/* Persist the station SSID (+ optional password; NULL/"" for an open network). */
esp_err_t aktualino_store_save_wifi(const char *ssid, const char *password);
/* Load the stored SSID/password. *present=false (empty outputs) when none set.
 * Either output buffer may be NULL. */
esp_err_t aktualino_store_load_wifi(char *ssid_buf, size_t ssid_cap,
                                    char *pass_buf, size_t pass_cap,
                                    bool *present);

/*
 * Path B (bring-your-own) provisioning credential entered at runtime through the
 * portal — a bearer/provisioning token or a self-hosted enrolment token. Stored
 * so the self-enrol path can consume it, then cleared once provisioning
 * succeeds. *present=false when none stored. `buf` may be NULL to just probe.
 */
esp_err_t aktualino_store_have_prov_cred(bool *out);
esp_err_t aktualino_store_save_prov_cred(const char *cred);
esp_err_t aktualino_store_load_prov_cred(char *buf, size_t cap, bool *present);
esp_err_t aktualino_store_clear_prov_cred(void);

/* On-device Uptane ECU signing keypair (Ed25519): pk=32 raw, sk=64 libsodium. */
esp_err_t aktualino_store_have_ecu_key(bool *out);
esp_err_t aktualino_store_save_ecu_key(const uint8_t pk[32], const uint8_t sk[64]);
esp_err_t aktualino_store_load_ecu_key(uint8_t pk[32], uint8_t sk[64]);

/* Provisioned flag: set true only after creds + ECU register + first manifest
 * all succeed (SPEC §6). */
esp_err_t aktualino_store_set_provisioned(bool value);
esp_err_t aktualino_store_is_provisioned(bool *out);

/*
 * Stable per-device identity nonce. Folded into the device name and ECU serial
 * so a re-provisioned board never collides with a stale server-side record from
 * an earlier enrolment (SPEC §8 "previously registered elsewhere" sharp edge)
 * and two boards can never share a MAC-derived ECU serial. Generated once (from
 * `fresh`, e.g. esp_random()) and persisted; returned verbatim thereafter. */
esp_err_t aktualino_store_get_or_init_id_nonce(uint32_t fresh, uint32_t *out);

/* Store/fetch a named TUF metadata blob (e.g. "director/root"), versioned. */
esp_err_t aktualino_store_put_metadata(const char *name,
                                       const void *buf, size_t len);
esp_err_t aktualino_store_get_metadata(const char *name,
                                       void *buf, size_t cap, size_t *out_len);

/*
 * Per-role TUF metadata version, for anti-rollback / monotonicity (SPEC §7.2).
 * `role` is a short tag: "root" | "timestamp" | "snapshot" | "targets".
 * get returns 0 via *out when no version has ever been stored (first boot);
 * set persists the new (higher) version after a role verifies.
 */
esp_err_t aktualino_store_get_meta_version(const char *role, int32_t *out);
esp_err_t aktualino_store_set_meta_version(const char *role, int32_t version);

/* ------------------------------------------------------------------ *
 * Install state (Phase 3 — full update loop).
 *
 * "running image" is the Director target currently installed and confirmed on
 * the active slot: its {filepath, sha256, length}. The poll loop compares an
 * assignment's sha256 against this recorded sha256 to decide whether to update
 * (Director-driven, avoids reflash loops). A fresh Phase-1 device has none.
 *
 * "pending update" is a target that has been downloaded + set-boot but not yet
 * confirmed after reboot: {filepath, sha256, length, correlation_id}. Persisted
 * before the reboot so the freshly-booted image knows what it installed and
 * which assignment correlation_id to report — idempotent across power loss.
 * ------------------------------------------------------------------ */

/* Record/clear the confirmed running image (the installed Director target). */
esp_err_t aktualino_store_set_running_image(const char *filepath,
                                            const uint8_t sha256[32],
                                            uint32_t length);
/* Load the running image. *present=false (and empty outputs) when never set.
 * `filepath` is copied into fp_buf (<=fp_cap); any output pointer may be NULL. */
esp_err_t aktualino_store_get_running_image(char *fp_buf, size_t fp_cap,
                                            uint8_t sha256[32], uint32_t *length,
                                            bool *present);

/* Stage/clear the pending (downloaded, not-yet-confirmed) update. */
esp_err_t aktualino_store_set_pending_update(const char *filepath,
                                             const uint8_t sha256[32],
                                             uint32_t length,
                                             const char *correlation_id);
esp_err_t aktualino_store_get_pending_update(char *fp_buf, size_t fp_cap,
                                             uint8_t sha256[32], uint32_t *length,
                                             char *cid_buf, size_t cid_cap,
                                             bool *present);
esp_err_t aktualino_store_clear_pending_update(void);

/*
 * Clear ALL TUF metadata while keeping device identity (SPEC §8 sharp edge).
 * Called on re-provision so a stale, higher-version root can be replaced.
 */
esp_err_t aktualino_store_reset_tuf(void);

/*
 * Full factory reset: clear device identity + ECU key + provisioned flag AND
 * all stored TUF metadata (SPEC §8). After this the device re-provisions from
 * scratch on the next boot.
 */
esp_err_t aktualino_store_reset(void);

#ifdef __cplusplus
}
#endif
