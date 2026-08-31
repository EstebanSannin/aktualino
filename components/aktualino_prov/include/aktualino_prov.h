/*
 * aktualino_prov — device provisioning (SPEC §5, §6, §6.1).
 *
 * Flow (SPEC §6, OTA-Connect device protocol against Torizon Cloud):
 *   1. Obtain per-device credentials from Torizon Cloud provisioning
 *      (device.zip): { uuid, gatewayUrl, client (PEM), pkey (PEM), cacert (PEM) }
 *      — the per-device mTLS identity + pinned server CA. This is done either
 *      on-device by aktualino_prov_torizon_fetch_creds() or by a host injector
 *      (tools/aktualino-provision.py) writing the NVS credential schema.
 *   2. Persist via aktualino_store (device cert/key, server CA, gateway, uuid).
 *   3. ECU-register with the Director: generate an on-device Ed25519 ECU key
 *      (aktualino_crypto) and POST /director/ecus with the public key
 *      (SPEC Appendix A). The mTLS key and the ECU key (Ed25519, on-device) are
 *      DISTINCT — do not conflate them (SPEC §6.1).
 *   4. First manifest PUT /director/manifest establishes the device as current.
 *
 * This component does the device-side self-enrol (steps 3-4) once the credentials
 * from step 1-2 are present in the store.
 */
#pragma once

#include <stddef.h>
#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Inputs for the ECU-register + manifest self-enrol (SPEC §6.1). Credentials are
 * loaded from aktualino_store; these only tune identity + CA pinning. */
typedef struct {
    const char *device_name;  /* device name; NULL => MAC-derived */
    const char *hardware_id;  /* Uptane hardware_identifier, e.g. aktualino-esp32 */
    const char *server_ca_pem; /* embedded gateway CA to pin for mTLS; NULL => use
                                * the cacert stored at provisioning */
} aktualino_prov_inputs_t;

/*
 * Finish the self-enrol flow (SPEC §6 steps 3-4): generate the ECU key, register
 * the ECU with the Director, and send the first manifest. Requires per-device
 * credentials to already be in the store (see aktualino_prov_torizon_fetch_creds
 * or a host injector). Idempotent-ish: safe to call when already provisioned
 * (returns ESP_OK once aktualino_store reports the device provisioned).
 */
esp_err_t aktualino_prov_run(const aktualino_prov_inputs_t *inputs);

/* True (via *out) once a completed provisioning identity exists in the store. */
esp_err_t aktualino_prov_is_provisioned(bool *out);

/*
 * Torizon Cloud on-device self-provision — obtain per-device credentials
 * (Path A2 baked provision.json, or Path B a runtime-pasted credential) and
 * persist them so aktualino_prov_run() can register the ECU + first manifest.
 *
 * Steps (the exact calls tools/aktualino-provision.py validated, moved
 * on-device):
 *   1. Mint an OAuth2 access token via the client_credentials grant at
 *      `token_endpoint` using {client_id, client_secret} — UNLESS a ready
 *      `bearer_token` is supplied (Path B paste of a durable provisioning
 *      token), in which case that is used directly.
 *   2. POST `devices_url` (Bearer) with {device_id, device_name} -> device.zip.
 *   3. Inflate device.zip (miniz) and extract client.pem / pkey.pem / root.crt /
 *      gateway.url / info.json; save as the device identity (aktualino_store).
 *   4. Seed the Torizon Director + Image RSA root trust anchors into NVS (from
 *      the supplied roots) so the poll loop verifies against Torizon.
 *
 * device_id/device_name are MAC+nonce-derived when NULL. Returns ESP_OK once the
 * device identity is stored; the caller then runs aktualino_prov_run() to finish
 * ECU registration + the first manifest.
 *
 * DEV-ONLY when baked (A2): a firmware carrying client_secret can register
 * devices in the account — it needs flash encryption in production and must
 * never be published (docs/provisioning.md Path A2 tradeoff).
 */
typedef struct {
    const char *token_endpoint;   /* provision.json token_endpoint (OAuth2)      */
    const char *client_id;        /* provision.json client_id                    */
    const char *client_secret;    /* provision.json secret [SECRET]; NULL if bearer */
    const char *bearer_token;     /* ready access token (Path B); NULL to mint   */
    const char *devices_url;      /* POST target; NULL => app.torizon.io default */
    const char *device_id;        /* NULL => MAC+nonce-derived                   */
    const char *device_name;      /* NULL => same as device_id                   */
    const char *director_root_json;  /* Torizon director.root.json (seed anchor) */
    size_t      director_root_len;
    const char *image_root_json;     /* Torizon image root.json (seed anchor)    */
    size_t      image_root_len;
} aktualino_prov_torizon_inputs_t;

esp_err_t aktualino_prov_torizon_fetch_creds(
    const aktualino_prov_torizon_inputs_t *in);

/*
 * Re-send the V3 device manifest for the currently-running firmware
 * (PUT /director/manifest, mTLS), signed by the stored on-device Ed25519 ECU
 * key. Keeps the device "current" in the director between polls (SPEC §7.8).
 * Loads creds + ECU key from the store; `hardware_id` (NULL => "aktualino-esp32")
 * names the installed_image filepath. Returns ESP_OK on HTTP 200/204.
 */
esp_err_t aktualino_prov_report_current(const char *hardware_id);

/*
 * Report an installed Director target with a V3 installation_report so the
 * director marks the matching assignment completed (Phase 3, SPEC §7.8). The
 * manifest's installed_image is exactly {filepath, sha256, length} — which MUST
 * equal the assigned target — and the report carries `correlation_id` and
 * `success`. Signed with the stored on-device Ed25519 ECU key over mTLS.
 * Returns ESP_OK on HTTP 200/204.
 */
esp_err_t aktualino_prov_report_installed(const char *filepath,
                                          const uint8_t sha256[32],
                                          uint32_t length,
                                          const char *correlation_id,
                                          bool success);

/*
 * Report a FAILED install for `correlation_id` (SPEC §7.8). The manifest's
 * installed_image is the currently-running (unchanged / rolled-back) image and
 * the installation_report result is failure — so the director cancels the
 * assignment and records the failure. `hardware_id` (NULL => "aktualino-esp32")
 * names the fallback installed_image when no Director target is yet recorded.
 */
esp_err_t aktualino_prov_report_failed(const char *hardware_id,
                                       const char *correlation_id);

#ifdef __cplusplus
}
#endif
