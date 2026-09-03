/*
 * aktualino_portal — on-device SoftAP captive-portal provisioning (SPEC §6.1,
 * docs/provisioning.md). The default field UX for a shell-less ESP32: an
 * unprovisioned board with no Wi-Fi credentials boots as a Wi-Fi access point
 * with a device-unique SSID (aktualino-<mac6>), serves a captive setup page, and
 * self-enrols against the OTA backend once the operator supplies Wi-Fi (Path A)
 * or Wi-Fi + a provisioning credential (Path B).
 *
 * This component owns the SoftAP/STA Wi-Fi bring-up, the captive DNS responder,
 * and the HTTP server (GET / /config /scan /status, POST /provision). It is
 * backend-agnostic: the OTA-backend enrolment sequence (obtain credentials,
 * register the ECU, first manifest) is supplied by the caller as a
 * aktualino_portal_provision_fn, so aktualino_portal never depends on the
 * specific backend. Wi-Fi join is done here (JOINING_WIFI) before the
 * driver runs; the driver streams the remaining progress via
 * aktualino_portal_set_state().
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Progress states streamed to the page's GET /status poller (SPEC §5 flow). */
typedef enum {
    AKT_PORTAL_IDLE = 0,        /* portal up, nothing submitted yet          */
    AKT_PORTAL_JOINING_WIFI,    /* connecting STA to the chosen network      */
    AKT_PORTAL_SNTP,            /* secure-time sync                          */
    AKT_PORTAL_REQUESTING_CREDS,/* obtaining the device credential           */
    AKT_PORTAL_REGISTERING,     /* ECU register + first manifest             */
    AKT_PORTAL_VERIFYING,       /* Uptane metadata verification              */
    AKT_PORTAL_DONE,            /* provisioned                               */
    AKT_PORTAL_ERROR,           /* failed (see the error detail)             */
} aktualino_portal_state_t;

/* What the operator submitted through the page (POST /provision). */
typedef struct {
    char ssid[33];          /* target Wi-Fi SSID (<=32)                     */
    char password[65];      /* Wi-Fi password ("" for an open network)      */
    char credential[2048];  /* Path B: pasted provisioning credential ("" if none) */
    char device_name[48];   /* optional device name ("" => MAC-derived)     */
} aktualino_portal_submit_t;

/*
 * OTA-backend enrolment driver, supplied by the caller. Called after the portal
 * has joined the chosen Wi-Fi and confirmed an IP. It must run the backend
 * sequence (secure time, obtain credential, ECU register, first manifest),
 * calling aktualino_portal_set_state() to advance the page, and return ESP_OK on
 * success (portal then moves to DONE) or an esp_err_t on failure (portal moves
 * to ERROR). `sub` is the operator's submission; `user` is cfg.user.
 */
typedef esp_err_t (*aktualino_portal_provision_fn)(
    const aktualino_portal_submit_t *sub, void *user);

typedef struct {
    const char *backend_name;   /* shown on the page, e.g. "Torizon Cloud"   */
    const char *hardware_id;    /* Uptane hardware id, e.g. "aktualino-esp32" */
    bool credential_needed;     /* Path B (true: ask for a credential) vs
                                 * Path A (false: creds baked/injected)       */
    aktualino_portal_provision_fn provision;  /* backend enrolment driver     */
    void *user;                 /* opaque, passed to provision()              */
} aktualino_portal_cfg_t;

/*
 * Bring up APSTA Wi-Fi (open AP, SSID aktualino-<mac6> from the factory MAC's
 * last 3 bytes), the captive DNS responder, and the HTTP server. Does its own
 * esp_netif/event/Wi-Fi init, so the caller must NOT have started Wi-Fi. Returns
 * after the services are running; provisioning happens asynchronously when the
 * page POSTs /provision. Never call twice.
 */
esp_err_t aktualino_portal_start(const aktualino_portal_cfg_t *cfg);

/* The AP SSID this board advertises (aktualino-<mac6>); valid after start. */
const char *aktualino_portal_ap_ssid(void);

/* Join the chosen Wi-Fi as STA (used internally before the driver runs; also
 * usable by the driver if it needs to re-check). Blocks up to timeout_ms. */
esp_err_t aktualino_portal_sta_connect(const char *ssid, const char *password,
                                       int timeout_ms);

/* Driver progress hooks (thread-safe). `detail` is a short mono string shown on
 * the page (may be NULL). set_state(ERROR, msg) also records the error text. */
void aktualino_portal_set_state(aktualino_portal_state_t st, const char *detail);
/* Record the enrolled device UUID for the success card (optional). */
void aktualino_portal_set_uuid(const char *uuid);

#ifdef __cplusplus
}
#endif
