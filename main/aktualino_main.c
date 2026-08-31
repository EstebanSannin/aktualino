/*
 * aktualino_main.c — Phase-0 app entry (SPEC §5, §7, §9, §10; WORKPLAN T0.4/T0.7).
 *
 * Brings the board up and runs a Phase-0 A/B OTA loop against the dumb TLS
 * update server (tools/dumb-update-server.py):
 *   1. Boot banner: app version, running partition, OTA image state.
 *   2. WiFi STA bring-up (creds via main/wifi_credentials.h else Kconfig).
 *   3. SNTP secure time (aktualino_time).
 *   4. Post-OTA decision: if the running image is PENDING_VERIFY (a slot we just
 *      installed and rebooted into), a successful boot + WiFi + SNTP is the
 *      Phase-0 self-check -> mark it valid (esp_ota_mark_app_valid_cancel_
 *      rollback). Under AKTUALINO_ROLLBACK_TEST we deliberately SKIP the confirm
 *      and reboot so the bootloader rolls back to the previous good slot.
 *   5. OTA attempt: GET the served image over HTTPS (pinned self-signed CA,
 *      embedded via EMBED_TXTFILES). If its esp_app_desc version is newer than
 *      the running image, install it into the inactive slot, set boot, reboot.
 *      Otherwise skip. One attempt per boot, then park in IDLE.
 */
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_app_desc.h"
#include "nvs_flash.h"

#include "driver/gpio.h"

#include "aktualino_core.h"
#include "aktualino_time.h"
#include "aktualino_ota.h"
#include "aktualino_prov.h"
#include "aktualino_store.h"
#include "aktualino_portal.h"

#if CONFIG_AKTUALINO_SCRIPT_SECONDARY
#include "aktualino_berry.h"    /* optional Berry script secondary (Kconfig-gated) */
#include "aktualino_script.h"   /* the secondary's install + run + report logic */
#endif

/*
 * A2 baked Torizon provisioning client (dev-only). main/provision_client.h is
 * generated at build time by tools/sync-build.sh from
 * secrets/torizon/extracted/provision.json + the two Torizon RSA roots, and is
 * .gitignored (it carries the account client_secret). When present the device
 * can self-provision to Torizon Cloud with no per-device injection and no pasted
 * credential (Path A2). NEVER commit it; needs flash encryption for production
 * (docs/provisioning.md Path A2 tradeoff).
 */
#if defined(__has_include)
#  if __has_include("provision_client.h")
#    include "provision_client.h"
#  endif
#endif

/* Uptane hardware_identifier for target selection + manifest reporting. */
#ifndef AKTUALINO_HARDWARE_ID
#  define AKTUALINO_HARDWARE_ID "aktualino-esp32"
#endif

/*
 * WiFi credentials. main/wifi_credentials.h is generated at build time by
 * tools/sync-build.sh from secrets/wifi.env and is .gitignored. When it is
 * absent we fall back to the Kconfig values (menu "Aktualino").
 */
#if defined(__has_include)
#  if __has_include("wifi_credentials.h")
#    include "wifi_credentials.h"
#  endif
#endif

#ifndef AKTUALINO_WIFI_SSID
#  define AKTUALINO_WIFI_SSID CONFIG_AKTUALINO_WIFI_SSID
#endif
#ifndef AKTUALINO_WIFI_PASS
#  define AKTUALINO_WIFI_PASS CONFIG_AKTUALINO_WIFI_PASS
#endif

#ifdef CONFIG_AKTUALINO_SNTP_SERVER
#  define AKTUALINO_SNTP_SERVER CONFIG_AKTUALINO_SNTP_SERVER
#else
#  define AKTUALINO_SNTP_SERVER "pool.ntp.org"
#endif

/*
 * Pinned Director root.json TRUST ANCHOR (SPEC §7, Phase 2). Public Uptane
 * metadata embedded at build time (main/embed/director_root.json, EMBED_TXTFILES)
 * so the device is TOFU-free: it verifies the fetched root against this and walks
 * the rotation chain forward. NUL-terminated by EMBED_TXTFILES; _end - _start
 * gives the exact length (minus the trailing NUL).
 */
extern const char director_root_json_start[] asm("_binary_director_root_json_start");
extern const char director_root_json_end[]   asm("_binary_director_root_json_end");

/*
 * Pinned IMAGE-repo root.json TRUST ANCHOR (SPEC §7, Phase 4a). A SECOND,
 * independent Uptane trust anchor (own keys, own NVS namespace) for the /repo
 * user_repo. The device verifies fetched image roles against this and walks the
 * image rotation chain forward — enabling the two-repo cross-check.
 */
extern const char image_root_json_start[] asm("_binary_image_root_json_start");
extern const char image_root_json_end[]   asm("_binary_image_root_json_end");

static const char *TAG = "akt_main";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
#define WIFI_MAX_RETRY     10
#define SNTP_TIMEOUT_MS    30000
/* Phase-2 Director poll cadence + how often to re-assert the device manifest. */
#define POLL_INTERVAL_MS       30000
#define MANIFEST_EVERY_N_POLLS 10
/* Grace before the single per-boot OTA attempt: gives an operator time to
 * (re)point/stop the dumb server between test stages and keeps a rollback
 * demo from re-installing the self-destructing image in a tight loop. */
#define OTA_START_DELAY_MS 8000

static EventGroupHandle_t s_wifi_events;
static int s_wifi_retries;

static void on_wifi_event(void *arg, esp_event_base_t base,
                          int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_wifi_retries < WIFI_MAX_RETRY) {
            s_wifi_retries++;
            ESP_LOGW(TAG, "WiFi disconnected; retry %d/%d",
                     s_wifi_retries, WIFI_MAX_RETRY);
            esp_wifi_connect();
        } else {
            ESP_LOGE(TAG, "WiFi failed after %d retries", WIFI_MAX_RETRY);
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "got IP: " IPSTR, IP2STR(&ev->ip_info.ip));
        s_wifi_retries = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

/*
 * STA bring-up for the normal (already-have-Wi-Fi) boot path. `ssid`/`pass` come
 * from resolve_wifi() (NVS creds written by the portal/CLI take priority over the
 * build-time fallback). Blocks until connected or WIFI_MAX_RETRY exhausted.
 */
static esp_err_t wifi_connect(const char *ssid, const char *pass)
{
    s_wifi_events = xEventGroupCreate();
    if (!s_wifi_events) {
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &on_wifi_event, NULL, NULL));

    wifi_config_t wc = { 0 };
    strncpy((char *)wc.sta.ssid, ssid, sizeof(wc.sta.ssid) - 1);
    strncpy((char *)wc.sta.password, pass ? pass : "", sizeof(wc.sta.password) - 1);
    wc.sta.threshold.authmode = (pass && pass[0]) ? WIFI_AUTH_WPA2_PSK
                                                   : WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));

    ESP_LOGI(TAG, "connecting to SSID \"%s\"...", ssid);
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        return ESP_OK;
    }
    return ESP_FAIL;
}

/*
 * Resolve the Wi-Fi station credentials for the normal boot path: NVS creds
 * (written by the SoftAP portal or the host CLI) take priority; the build-time
 * wifi_credentials.h / Kconfig fallback is used only when NVS has none. Returns
 * true and fills the buffers when a usable SSID was found.
 */
static bool resolve_wifi(char *ssid, size_t ssid_cap, char *pass, size_t pass_cap)
{
    bool have = false;
    aktualino_store_load_wifi(ssid, ssid_cap, pass, pass_cap, &have);
    if (have && ssid[0]) {
        ESP_LOGI(TAG, "using Wi-Fi credentials from NVS (SSID \"%s\")", ssid);
        return true;
    }
#ifdef AKTUALINO_HAVE_BAKED_WIFI
    strncpy(ssid, AKTUALINO_WIFI_SSID, ssid_cap - 1); ssid[ssid_cap-1] = '\0';
    strncpy(pass, AKTUALINO_WIFI_PASS, pass_cap - 1); pass[pass_cap-1] = '\0';
    ESP_LOGI(TAG, "using baked Wi-Fi credentials (SSID \"%s\")", ssid);
    return ssid[0] != '\0';
#else
    return false;
#endif
}

static void boot_banner(bool *out_pending_verify)
{
    const esp_app_desc_t *app = esp_app_get_description();
    uint8_t mac[6] = { 0 };
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    ESP_LOGI(TAG, "======================================================");
    ESP_LOGI(TAG, " Aktualino — tiny Uptane OTA client (Phase 4a: two-repo verify)");
    ESP_LOGI(TAG, " app: %s  version: %s", app->project_name, app->version);
    ESP_LOGI(TAG, " built: %s %s  idf: %s",
             app->date, app->time, app->idf_ver);
    ESP_LOGI(TAG, " sta mac: %02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#ifdef AKTUALINO_ROLLBACK_TEST
    ESP_LOGW(TAG, " *** AKTUALINO_ROLLBACK_TEST build: will NOT confirm a "
                  "freshly-OTA'd image (forces bootloader rollback) ***");
#endif
    ESP_LOGI(TAG, "======================================================");

    /* Running partition + OTA image state (SPEC §10). The confirm/rollback
     * decision is deferred to app_main until after the network self-check. */
    aktualino_ota_running_info(out_pending_verify);
}

/*
 * Phase-1 provisioning (SPEC §6): if the device is not yet provisioned but has
 * per-device credentials in NVS (injected by a host tool, e.g. Torizon Cloud
 * device.zip via tools/aktualino-provision.py), enrol the ECU + first manifest
 * against the stored gateway, pinning the stored cacert. Idempotent: a
 * provisioned device just logs and returns. A device with no credentials is
 * enrolled through the SoftAP portal instead (start_portal). The Phase-2 poll
 * loop is out of scope here.
 */
static void provision_if_needed(void)
{
    if (aktualino_store_init() != ESP_OK) {
        ESP_LOGE(TAG, "store init failed — cannot provision");
        return;
    }

    bool provisioned = false;
    aktualino_prov_is_provisioned(&provisioned);
    if (provisioned) {
        ESP_LOGI(TAG, "already provisioned — device is registered; idling");
        return;
    }

    bool have_creds = false;
    aktualino_store_have_creds(&have_creds);
    if (!have_creds) {
        ESP_LOGW(TAG, "no injected device credentials — enrol via the SoftAP "
                      "setup portal; idling");
        return;
    }
    ESP_LOGI(TAG, "pre-injected device credentials found — enrolling ECU + "
                  "first manifest against the stored gateway");

    aktualino_prov_inputs_t in = {
        .device_name   = NULL,                      /* MAC-derived */
        .hardware_id   = AKTUALINO_HARDWARE_ID,
        .server_ca_pem = NULL,                      /* pin the stored cacert */
    };
    esp_err_t err = aktualino_prov_run(&in);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "==================================================");
        ESP_LOGI(TAG, " PROVISIONING SUCCESS — device provisioned, ECU");
        ESP_LOGI(TAG, " registered, and first manifest accepted.");
        ESP_LOGI(TAG, "==================================================");
    } else {
        ESP_LOGE(TAG, "provisioning FAILED: %s", esp_err_to_name(err));
    }
}

/*
 * Post-boot update resolution (Phase 3, SPEC §7.7–§7.8). If a pending update is
 * staged in NVS, this boot is the result of installing it:
 *   - PENDING_VERIFY (we booted the new image): self-check passed (WiFi+SNTP OK)
 *     -> mark valid, PUT a manifest with installed_image = the new target and a
 *        success installation_report carrying the assignment correlation_id, then
 *        promote the running-image record and clear the pending record.
 *     (Under AKTUALINO_ROLLBACK_TEST we deliberately skip the confirm and reboot,
 *      forcing the bootloader to roll back so the failure path can be exercised.)
 *   - not PENDING_VERIFY but the inactive slot is INVALID/ABORTED: the new image
 *     failed and the bootloader rolled us back -> report the failure for the
 *     correlation_id and clear the pending record (staying on the good image).
 * With no pending update this is the Phase-0 plain confirm of a pending image.
 */
static void handle_post_boot(bool pending_verify)
{
    if (aktualino_store_init() != ESP_OK) return;

    char fp[254]; uint8_t sha[32]; uint32_t len = 0; char cid[128];
    bool pending = false;
    aktualino_store_get_pending_update(fp, sizeof(fp), sha, &len,
                                       cid, sizeof(cid), &pending);

    if (!pending) {
        if (pending_verify) {
            ESP_LOGI(TAG, "post-OTA self-check passed — confirming running image");
            aktualino_ota_mark_valid();
        }
        return;
    }

    ESP_LOGW(TAG, "pending update present: %s (cid=%s pending_verify=%d)",
             fp, cid[0] ? cid : "(none)", (int)pending_verify);

    if (pending_verify) {
#ifdef AKTUALINO_ROLLBACK_TEST
        ESP_LOGE(TAG, "ROLLBACK_TEST: NOT confirming freshly-OTA'd image — "
                      "rebooting so the bootloader rolls back");
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
#else
        const esp_app_desc_t *app = esp_app_get_description();
        ESP_LOGW(TAG, "==================================================");
        ESP_LOGW(TAG, " UPDATE BOOTED: now running %s — confirming + reporting",
                 app ? app->version : "?");
        ESP_LOGW(TAG, "==================================================");
        aktualino_ota_mark_valid();

        esp_err_t rc = aktualino_prov_report_installed(fp, sha, len, cid, true);
        if (rc == ESP_OK) {
            aktualino_store_set_running_image(fp, sha, len);
            aktualino_store_clear_pending_update();
            ESP_LOGW(TAG, "UPDATE COMPLETE — success manifest ACCEPTED, "
                          "running-image recorded, pending cleared");
        } else {
            ESP_LOGE(TAG, "success manifest failed (%s) — keeping pending, "
                          "will retry next poll", esp_err_to_name(rc));
        }
#endif
        return;
    }

    /* Not pending_verify but a pending update is staged: either a rollback, or a
     * confirm that succeeded but did not get cleared (power loss). */
    bool rolled_back = false;
    aktualino_ota_inactive_slot_failed(&rolled_back);
    if (rolled_back) {
        ESP_LOGE(TAG, "ROLLBACK detected — installed image failed its self-check; "
                      "reporting failure for cid=%s", cid[0] ? cid : "(none)");
        esp_err_t rc = aktualino_prov_report_failed(AKTUALINO_HARDWARE_ID, cid);
        ESP_LOGW(TAG, "failure report: %s",
                 rc == ESP_OK ? "ACCEPTED" : esp_err_to_name(rc));
        aktualino_store_clear_pending_update();
    } else {
        /* The pending slot is the one we're running on (already valid): finish
         * the report idempotently. */
        ESP_LOGW(TAG, "pending present without pending-verify and slot not failed "
                      "— finishing report idempotently for %s", fp);
        esp_err_t rc = aktualino_prov_report_installed(fp, sha, len, cid, true);
        if (rc == ESP_OK) {
            aktualino_store_set_running_image(fp, sha, len);
            aktualino_store_clear_pending_update();
        }
    }
}

/*
 * Phase-2 Director poll/verify loop (SPEC §7.1–§7.3, §9). Establishes the trust
 * anchor from the embedded root, then every POLL_INTERVAL_MS: walk the root
 * rotation, verify timestamp/snapshot/targets (signature threshold, expiry vs
 * SNTP, version monotonicity), and select any target for our hardware id. With
 * no target published the loop logs "no update assigned — up to date" and keeps
 * polling. Periodically re-asserts the device manifest so the device stays
 * current. Never returns while metadata verification is healthy.
 */
static void run_director_poll_loop(void)
{
    size_t root_len = (size_t)(director_root_json_end - director_root_json_start);
    time_t nowt = time(NULL);

    esp_err_t err = aktualino_core_trust_anchor_init(director_root_json_start,
                                                     root_len, (int64_t)nowt);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "trust anchor init failed: %s — cannot verify Director "
                      "metadata; parking", esp_err_to_name(err));
        return;
    }

    /* Phase 4a: the second (Image-repo) trust anchor, for the two-repo cross-check. */
    size_t img_root_len = (size_t)(image_root_json_end - image_root_json_start);
    err = aktualino_core_image_trust_anchor_init(image_root_json_start,
                                                 img_root_len, (int64_t)nowt);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "image trust anchor init failed: %s — cannot cross-verify "
                      "against the Image repo; parking", esp_err_to_name(err));
        return;
    }

    char iso[25];
    int poll = 0;
    for (;;) {
        /* Secure-time gate (SPEC §9): never verify expiry against a bad clock. */
        nowt = time(NULL);
        if (nowt < AKTUALINO_TIME_FLOOR_EPOCH) {
            ESP_LOGW(TAG, "clock %lld below sanity floor — re-syncing SNTP",
                     (long long)nowt);
            aktualino_time_sync(AKTUALINO_SNTP_SERVER, SNTP_TIMEOUT_MS);
            nowt = time(NULL);
        }

        poll++;
        ESP_LOGI(TAG, "======== Director poll #%d at %s ========",
                 poll, aktualino_time_iso8601(iso, sizeof(iso)));

        aktualino_poll_result_t res;
        err = aktualino_core_poll_director(AKTUALINO_HARDWARE_ID,
                                           (int64_t)nowt, &res);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "poll #%d OK — root=v%ld timestamp=v%ld snapshot=v%ld "
                          "targets=v%ld", poll, (long)res.root_version,
                     (long)res.timestamp_version, (long)res.snapshot_version,
                     (long)res.targets_version);
            if (res.target_assigned) {
                bool is_new = false;
                aktualino_core_target_is_new(&res, &is_new);
                if (!is_new) {
                    ESP_LOGI(TAG, "==> assigned target already installed — "
                                  "up to date (idempotent, no re-update)");
                } else {
                    ESP_LOGW(TAG, "state: POLL_DIRECTOR -> VERIFY_METADATA (cross-repo)");
                    ESP_LOGW(TAG, "UPDATE ASSIGNED: %s (len=%zu sha256=%s) — "
                                  "cross-verifying Image repo, then downloading",
                             res.target_path, res.target_length,
                             res.target_sha256_hex);
                    /* download_and_install runs the two-repo cross-check FIRST:
                     * it refuses to write flash unless the Image repo signs the
                     * identical target the Director assigned (SPEC §7, §15). */
                    esp_err_t drc = aktualino_core_download_and_install(&res, (int64_t)nowt);
                    if (drc == ESP_OK) {
                        ESP_LOGW(TAG, "state: VERIFY_METADATA -> DOWNLOAD -> INSTALL -> REBOOT");
                        ESP_LOGW(TAG, "both repos agree + image staged + verified — "
                                      "rebooting into the new image");
                        vTaskDelay(pdMS_TO_TICKS(1000));
                        esp_restart();
                    }
                    ESP_LOGE(TAG, "cross-repo/download/install refused: %s — reporting "
                                  "failure, staying on current image", esp_err_to_name(drc));
                    aktualino_prov_report_failed(AKTUALINO_HARDWARE_ID,
                                                 res.correlation_id);
                }
            } else {
                ESP_LOGI(TAG, "==> no update assigned — up to date");
            }
        } else {
            ESP_LOGE(TAG, "poll #%d FAILED: %s (staying on last-good metadata)",
                     poll, esp_err_to_name(err));
        }

#if CONFIG_AKTUALINO_SCRIPT_SECONDARY
        /* Second Uptane track: check the aktualino-lua bundle target, install +
         * run + report it (docs/berry-secondary-spec.md). Independent of the
         * primary A/B firmware flow; never reboots. */
        aktualino_script_poll((int64_t)nowt);
#endif

        /* Keep the device "current" in the director (first poll + periodically). */
        if (poll == 1 || (poll % MANIFEST_EVERY_N_POLLS) == 0) {
            esp_err_t mrc = aktualino_prov_report_current(AKTUALINO_HARDWARE_ID);
            ESP_LOGI(TAG, "manifest re-report: %s",
                     mrc == ESP_OK ? "ACCEPTED" : esp_err_to_name(mrc));
        }

        vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));
    }
}

/*
 * SoftAP captive-portal enrolment driver (SPEC §6.1). Invoked by aktualino_portal
 * after it has joined the operator-chosen Wi-Fi. Runs the backend sequence and
 * streams progress to the page:
 *   SNTP -> obtain device credential -> ECU register + first manifest -> verify.
 * Credential sources, in order:
 *   - already-present device creds (Path A1: host-injected NVS)  -> nothing to do,
 *   - baked Torizon provision client (Path A2)                   -> self-provision,
 *   - a runtime-pasted credential (Path B)                       -> self-provision.
 * Returns ESP_OK on success (portal shows DONE) or an esp_err_t (portal shows the
 * error). Verification is best-effort: the device is already provisioned and the
 * normal poll loop re-verifies on the next boot.
 */
static esp_err_t portal_provision_driver(const aktualino_portal_submit_t *sub,
                                         void *user)
{
    (void)user;

    aktualino_portal_set_state(AKT_PORTAL_SNTP, "SNTP");
    if (aktualino_time_sync(AKTUALINO_SNTP_SERVER, SNTP_TIMEOUT_MS) != ESP_OK) {
        aktualino_portal_set_state(AKT_PORTAL_ERROR, "secure time sync failed");
        return ESP_FAIL;
    }

    bool have_creds = false;
    aktualino_store_have_creds(&have_creds);
    if (!have_creds) {
        aktualino_portal_set_state(AKT_PORTAL_REQUESTING_CREDS, "Torizon Cloud");
#ifdef AKTUALINO_TORIZON_PROVISION
        aktualino_prov_torizon_inputs_t ti = {
            .token_endpoint = AKTUALINO_TORIZON_TOKEN_ENDPOINT,
            .client_id      = AKTUALINO_TORIZON_CLIENT_ID,
            .client_secret  = AKTUALINO_TORIZON_CLIENT_SECRET,
            /* A pasted credential (Path B) overrides the baked client. */
            .bearer_token   = sub->credential[0] ? sub->credential : NULL,
            .device_name    = sub->device_name[0] ? sub->device_name : NULL,
            .director_root_json = AKTUALINO_TORIZON_DIRECTOR_ROOT,
            .director_root_len  = sizeof(AKTUALINO_TORIZON_DIRECTOR_ROOT) - 1,
            .image_root_json    = AKTUALINO_TORIZON_IMAGE_ROOT,
            .image_root_len     = sizeof(AKTUALINO_TORIZON_IMAGE_ROOT) - 1,
        };
        esp_err_t fe = aktualino_prov_torizon_fetch_creds(&ti);
        if (fe != ESP_OK) {
            aktualino_portal_set_state(AKT_PORTAL_ERROR, "credential fetch failed");
            return fe;
        }
#else
        /* No baked client: only a pasted Path-B credential can self-provision.
         * Without baked Torizon roots the trust anchor is not seeded here — the
         * poll loop then needs Torizon roots from another injector (documented
         * limitation in docs/provisioning.md). */
        if (sub->credential[0]) {
            aktualino_prov_torizon_inputs_t ti = {
                .bearer_token = sub->credential,
                .device_name  = sub->device_name[0] ? sub->device_name : NULL,
            };
            esp_err_t fe = aktualino_prov_torizon_fetch_creds(&ti);
            if (fe != ESP_OK) {
                aktualino_portal_set_state(AKT_PORTAL_ERROR, "credential fetch failed");
                return fe;
            }
        } else {
            aktualino_portal_set_state(AKT_PORTAL_ERROR, "no provisioning credential");
            return ESP_ERR_INVALID_STATE;
        }
#endif
    } else {
        ESP_LOGI(TAG, "portal: device credentials already present — skipping fetch");
    }

    /* ECU register + first manifest (the validated injected-creds path). */
    aktualino_portal_set_state(AKT_PORTAL_REGISTERING, "Ed25519");
    aktualino_prov_inputs_t in = {
        .device_name   = sub->device_name[0] ? sub->device_name : NULL,
        .hardware_id   = AKTUALINO_HARDWARE_ID,
        .server_ca_pem = NULL,                       /* pin the stored cacert */
    };
    esp_err_t err = aktualino_prov_run(&in);
    if (err != ESP_OK) {
        aktualino_portal_set_state(AKT_PORTAL_ERROR, "device registration failed");
        return err;
    }

    /* Surface the enrolled UUID on the success card. */
    aktualino_creds_t creds;
    if (aktualino_store_load_creds(&creds) == ESP_OK) {
        aktualino_portal_set_uuid(creds.uuid);
        aktualino_store_free_creds(&creds);
    }

    /* Best-effort one-shot Uptane verify (the poll loop re-verifies next boot). */
    aktualino_portal_set_state(AKT_PORTAL_VERIFYING, "Uptane");
    time_t nowt = time(NULL);
    size_t drl = (size_t)(director_root_json_end - director_root_json_start);
    size_t irl = (size_t)(image_root_json_end - image_root_json_start);
    if (aktualino_core_trust_anchor_init(director_root_json_start, drl, (int64_t)nowt) == ESP_OK &&
        aktualino_core_image_trust_anchor_init(image_root_json_start, irl, (int64_t)nowt) == ESP_OK) {
        aktualino_poll_result_t res;
        esp_err_t pr = aktualino_core_poll_director(AKTUALINO_HARDWARE_ID, (int64_t)nowt, &res);
        ESP_LOGI(TAG, "portal verify poll: %s", esp_err_to_name(pr));
    }
    return ESP_OK;
}

/*
 * Bring up the SoftAP captive portal (SPEC §6.1) and park. Path A vs B is decided
 * by whether the board can self-provision without operator input: device creds
 * already injected (A1) or a baked Torizon client (A2) => Path A (Wi-Fi only);
 * otherwise Path B (the page also asks for a provisioning credential). After a
 * successful enrolment the device reboots into the normal poll loop.
 */
static void start_portal(void)
{
    bool have_creds = false;
    aktualino_store_have_creds(&have_creds);
    bool can_selfprovision = have_creds;
#ifdef AKTUALINO_TORIZON_PROVISION
    can_selfprovision = true;
#endif

    aktualino_portal_cfg_t cfg = {
        .backend_name      = "Torizon Cloud",
        .hardware_id       = AKTUALINO_HARDWARE_ID,
        .credential_needed = !can_selfprovision,
        .provision         = portal_provision_driver,
        .user              = NULL,
    };
    if (aktualino_portal_start(&cfg) != ESP_OK) {
        ESP_LOGE(TAG, "portal failed to start — parking in ERROR");
        return;
    }

#ifdef AKTUALINO_PORTAL_TEST_STA
    /* TEST-ONLY (AKT_PORTAL_TEST build): also join a baked Wi-Fi so the portal is
     * reachable from the wired LAN for curl-driven endpoint + provision tests
     * (a wired build host cannot join the ESP's AP). Not for production. */
# ifdef AKTUALINO_HAVE_BAKED_WIFI
    ESP_LOGW(TAG, "PORTAL_TEST_STA: joining baked Wi-Fi \"%s\" for LAN test access",
             AKTUALINO_WIFI_SSID);
    aktualino_portal_sta_connect(AKTUALINO_WIFI_SSID, AKTUALINO_WIFI_PASS, 30000);
# endif
#endif

    /* Park: reboot into the normal poll loop once enrolment completes; stay up on
     * error so the operator can retry from the page. */
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        bool prov = false;
        aktualino_store_is_provisioned(&prov);
        if (prov) {
            ESP_LOGW(TAG, "portal enrolment complete — rebooting into poll loop in 8s");
            vTaskDelay(pdMS_TO_TICKS(8000));
            esp_restart();
        }
    }
}

/*
 * Factory-reset-to-AP hook (SPEC §6.1, stubbed). If BOOT/GPIO0 is held LOW for
 * the full window early in app start, clear the device identity + Wi-Fi + TUF
 * metadata so the next boot re-opens the SoftAP portal (this also doubles as the
 * SPEC §8 stale-root reset). GPIO0 is the download-strap: it is HIGH by the time
 * the app runs unless the operator is deliberately holding the BOOT button, so a
 * normal boot never triggers this. A future build can debounce a longer hold or
 * count failed enrolments; kept minimal here.
 */
#define FACTORY_RESET_GPIO      GPIO_NUM_0
#define FACTORY_RESET_HOLD_MS   3000
static void maybe_factory_reset(void)
{
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << FACTORY_RESET_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    gpio_config(&io);
    if (gpio_get_level(FACTORY_RESET_GPIO) != 0) return;   /* not held — normal boot */

    ESP_LOGW(TAG, "BOOT held low — hold %d ms to factory-reset to setup portal",
             FACTORY_RESET_HOLD_MS);
    for (int waited = 0; waited < FACTORY_RESET_HOLD_MS; waited += 100) {
        if (gpio_get_level(FACTORY_RESET_GPIO) != 0) {
            ESP_LOGI(TAG, "BOOT released — factory reset cancelled");
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ESP_LOGW(TAG, "FACTORY RESET: clearing identity + Wi-Fi + TUF; re-opening portal");
    aktualino_store_init();
    aktualino_store_reset();
    esp_restart();
}

#if CONFIG_AKTUALINO_SCRIPT_SECONDARY
/*
 * S0 self-test for the Berry script secondary (docs/berry-secondary-spec.md).
 * Kconfig-gated, so a feature-off build is byte-identical to before. Runs a tiny
 * embedded bundle through the real on-target VM to prove it boots and links
 * (also what makes the app+Berry size measurable — without a reference the
 * runtime is garbage-collected out). Host-API bindings proper live in
 * aktualino_script (S3); these three natives are just enough to self-test.
 */
static volatile int s_berry_health;

static int akt_l_log(bvm *vm) {
    ESP_LOGI("berry", "%s", be_top(vm) >= 1 ? be_tostring(vm, 1) : "");
    be_return_nil(vm);
}
static int akt_l_report(bvm *vm) {
    int t = be_top(vm);
    const char *n = (t >= 1) ? be_tostring(vm, 1) : "?";
    long long v = (t >= 2 && be_isint(vm, 2)) ? (long long)be_toint(vm, 2) : 0;
    ESP_LOGI("berry", "report %s=%lld", n, v);
    be_return_nil(vm);
}
static int akt_l_health(bvm *vm) { s_berry_health = 1; be_return_nil(vm); }

static void berry_s0_selftest(void)
{
    static const char SRC[] =
        "def setup() log('berry v1.1.0 up') end\n"
        "def loop() report('tick', 1) health_ok() end\n";
    uint32_t heap0 = esp_get_free_heap_size();
    akt_berry_t *rt = akt_berry_new();
    if (!rt) { ESP_LOGE(TAG, "berry: vm alloc failed"); return; }
    akt_berry_register(rt, "log",       akt_l_log);
    akt_berry_register(rt, "report",    akt_l_report);
    akt_berry_register(rt, "health_ok", akt_l_health);
    if (akt_berry_load(rt, "selftest", SRC, sizeof(SRC) - 1) != 0) {
        ESP_LOGE(TAG, "berry: bundle load failed: %s", akt_berry_last_error(rt));
        akt_berry_free(rt);
        return;
    }
    akt_berry_call(rt, "setup");
    akt_berry_call(rt, "loop");
    ESP_LOGI(TAG, "berry S0 selftest: %s (VM heap cost ~%u B)",
             s_berry_health ? "OK (heartbeat seen)" : "NO HEARTBEAT",
             (unsigned)(heap0 - esp_get_free_heap_size()));
    akt_berry_free(rt);
}
#endif /* CONFIG_AKTUALINO_SCRIPT_SECONDARY */

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    aktualino_state_t st = AKT_STATE_BOOT;
    ESP_LOGI(TAG, "state: <reset> -> %s", aktualino_state_name(st));

    bool pending_verify = false;
    boot_banner(&pending_verify);

#if CONFIG_AKTUALINO_SCRIPT_SECONDARY
    berry_s0_selftest();          /* prove the Berry runtime boots on-target (S0) */
    aktualino_script_init();      /* locate the scripts partition; run any installed bundle */
#endif

    /* Factory-reset-to-AP hook (SPEC §6.1, stubbed): a held BOOT button clears
     * identity + Wi-Fi + TUF and reboots into the portal. */
    maybe_factory_reset();

    /*
     * Boot decision (SPEC §5, §6.1):
     *   provisioned              -> normal poll loop (below, needs Wi-Fi),
     *   else Wi-Fi creds known   -> connect + self-enrol (current behavior),
     *   else                     -> SoftAP captive portal (AP mode).
     */
    if (aktualino_store_init() != ESP_OK) {
        ESP_LOGE(TAG, "store init failed; parking in ERROR");
        st = aktualino_transition(st, AKT_STATE_ERROR);
        goto park;
    }
    bool provisioned = false;
    aktualino_store_is_provisioned(&provisioned);

    char ssid[33] = { 0 }, pass[65] = { 0 };
    bool have_wifi = resolve_wifi(ssid, sizeof(ssid), pass, sizeof(pass));

#ifdef AKTUALINO_PORTAL_TEST_STA
    bool force_portal = !provisioned;   /* TEST build: always demo the portal */
#else
    bool force_portal = false;
#endif

    if (!provisioned && (force_portal || !have_wifi)) {
        ESP_LOGW(TAG, "unprovisioned + no usable Wi-Fi%s — starting SoftAP setup portal",
                 force_portal ? " (forced by AKT_PORTAL_TEST)" : "");
        st = aktualino_transition(st, AKT_STATE_PROVISION);
        start_portal();                 /* parks; reboots into poll loop on success */
        st = aktualino_transition(st, AKT_STATE_ERROR);
        goto park;
    }

    /* BOOT -> TIME_SYNC: need the network up first for SNTP. */
    if (wifi_connect(ssid, pass) != ESP_OK) {
        ESP_LOGE(TAG, "WiFi bring-up failed; parking in ERROR");
        st = aktualino_transition(st, AKT_STATE_ERROR);
        goto park;
    }

    st = aktualino_transition(st, AKT_STATE_TIME_SYNC);
    if (aktualino_time_sync(AKTUALINO_SNTP_SERVER, SNTP_TIMEOUT_MS) != ESP_OK) {
        ESP_LOGE(TAG, "SNTP sync failed; parking in ERROR");
        st = aktualino_transition(st, AKT_STATE_ERROR);
        goto park;
    }

    /*
     * Post-OTA confirm/report (SPEC §7.7–§7.8). Handles a Phase-3 pending update
     * (report success + promote, or detect a rollback and report failure) and
     * the Phase-0 plain confirm. Requires the network (done above) for the
     * manifest PUT.
     */
    st = aktualino_transition(st, AKT_STATE_CONFIRM);
    handle_post_boot(pending_verify);

    /* Phase-1: finish enrolment for a device with injected creds (register ECU +
     * first manifest). */
    st = aktualino_transition(st, AKT_STATE_PROVISION);
    provision_if_needed();

    /* Phase-2: if provisioned, enter the Director poll/verify loop (never
     * returns while healthy). Otherwise park in IDLE. */
    {
        bool prov = false;
        aktualino_prov_is_provisioned(&prov);
        if (prov) {
            st = aktualino_transition(st, AKT_STATE_POLL_DIRECTOR);
            run_director_poll_loop();
            ESP_LOGE(TAG, "poll loop exited (trust-anchor/creds problem)");
            st = aktualino_transition(st, AKT_STATE_ERROR);
        } else {
            ESP_LOGW(TAG, "not provisioned — cannot poll Director; idling");
            st = aktualino_transition(st, AKT_STATE_IDLE);
        }
    }

park:
    {
        char iso[25];
        for (;;) {
            if (st == AKT_STATE_IDLE) {
                ESP_LOGI(TAG, "IDLE — up at %s (provisioning done)",
                         aktualino_time_iso8601(iso, sizeof(iso)));
            } else {
                ESP_LOGE(TAG, "ERROR — halted; check logs above");
            }
            vTaskDelay(pdMS_TO_TICKS(60000));
        }
    }
}
