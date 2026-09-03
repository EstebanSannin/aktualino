/*
 * aktualino_portal — SoftAP captive-portal provisioning (SPEC §6.1).
 *
 * Brings up APSTA Wi-Fi (open AP aktualino-<mac6>), a captive DNS responder that
 * points every A query at the AP IP, and an esp_http_server serving the embedded
 * gzipped setup page plus the JSON control endpoints. On POST /provision it saves
 * the Wi-Fi creds, joins the chosen network as STA (the AP stays up so the phone
 * keeps the page), then runs the caller-supplied backend enrolment driver,
 * streaming progress to GET /status.
 *
 * The AP is intentionally OPEN for this milestone. TODO(security, SPEC §6.1):
 * before field use, switch to WPA2 with a per-device AP password and add a
 * proof-of-possession handshake (esp_wifi_provisioning session encryption) so a
 * bystander can neither open the portal nor read the credential in flight.
 */
#include "aktualino_portal.h"

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_http_server.h"

#include "cJSON.h"

#include "aktualino_store.h"

static const char *TAG = "akt_portal";

/* Embedded gzipped setup page (components/aktualino_portal/www/portal.html,
 * gzipped and linked in by target_add_binary_data in CMakeLists.txt). */
extern const uint8_t portal_html_gz_start[] asm("_binary_portal_html_gz_start");
extern const uint8_t portal_html_gz_end[]   asm("_binary_portal_html_gz_end");

/* STA join synchronization. */
#define STA_CONNECTED_BIT BIT0
#define STA_FAIL_BIT      BIT1
#define STA_MAX_RETRY     8

static EventGroupHandle_t s_sta_events;
static int                s_sta_retries;
static bool               s_sta_connecting;   /* gate retries to the join window */
static char               s_ap_ssid[24];      /* "aktualino-<mac6>" */
static uint32_t           s_ap_ip;            /* AP IP for captive DNS (network order) */
static aktualino_portal_cfg_t s_cfg;

/* Provisioning progress, polled by GET /status. */
static volatile aktualino_portal_state_t s_state = AKT_PORTAL_IDLE;
static char s_detail[64];
static char s_error[96];
static char s_uuid[80];
static bool s_submitted;                       /* one provision attempt at a time */

/* ---- progress hooks ---------------------------------------------------- */
static const char *state_name(aktualino_portal_state_t st)
{
    switch (st) {
    case AKT_PORTAL_IDLE:             return "idle";
    case AKT_PORTAL_JOINING_WIFI:     return "joining_wifi";
    case AKT_PORTAL_SNTP:             return "sntp";
    case AKT_PORTAL_REQUESTING_CREDS: return "requesting_creds";
    case AKT_PORTAL_REGISTERING:      return "registering";
    case AKT_PORTAL_VERIFYING:        return "verifying";
    case AKT_PORTAL_DONE:             return "done";
    case AKT_PORTAL_ERROR:            return "error";
    }
    return "idle";
}

void aktualino_portal_set_state(aktualino_portal_state_t st, const char *detail)
{
    s_state = st;
    if (detail) { strncpy(s_detail, detail, sizeof(s_detail) - 1); s_detail[sizeof(s_detail)-1] = '\0'; }
    else s_detail[0] = '\0';
    if (st == AKT_PORTAL_ERROR && detail) {
        strncpy(s_error, detail, sizeof(s_error) - 1); s_error[sizeof(s_error)-1] = '\0';
    }
    ESP_LOGI(TAG, "portal state -> %s%s%s", state_name(st),
             detail ? " : " : "", detail ? detail : "");
}

void aktualino_portal_set_uuid(const char *uuid)
{
    if (!uuid) return;
    strncpy(s_uuid, uuid, sizeof(s_uuid) - 1); s_uuid[sizeof(s_uuid)-1] = '\0';
}

const char *aktualino_portal_ap_ssid(void) { return s_ap_ssid; }

/* ---- Wi-Fi events ------------------------------------------------------ */
static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = (wifi_event_ap_staconnected_t *)data;
        ESP_LOGI(TAG, "portal client joined: " MACSTR, MAC2STR(e->mac));
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_sta_connecting && s_sta_retries < STA_MAX_RETRY) {
            s_sta_retries++;
            ESP_LOGW(TAG, "STA disconnected; retry %d/%d", s_sta_retries, STA_MAX_RETRY);
            esp_wifi_connect();
        } else if (s_sta_connecting) {
            xEventGroupSetBits(s_sta_events, STA_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "STA got IP: " IPSTR, IP2STR(&ev->ip_info.ip));
        s_sta_retries = 0;
        xEventGroupSetBits(s_sta_events, STA_CONNECTED_BIT);
    }
}

esp_err_t aktualino_portal_sta_connect(const char *ssid, const char *password,
                                       int timeout_ms)
{
    if (!ssid || !ssid[0]) return ESP_ERR_INVALID_ARG;

    /* Already associated to the requested SSID (e.g. the AKT_PORTAL_TEST pre-join,
     * or a retry)? esp_wifi_connect() would then raise no fresh GOT_IP event and
     * the wait below would spuriously time out — short-circuit to success. */
    wifi_ap_record_t cur;
    if (esp_wifi_sta_get_ap_info(&cur) == ESP_OK &&
        strncmp((const char *)cur.ssid, ssid, sizeof(cur.ssid)) == 0) {
        ESP_LOGI(TAG, "STA already connected to \"%s\"", ssid);
        return ESP_OK;
    }

    wifi_config_t wc = { 0 };
    strncpy((char *)wc.sta.ssid, ssid, sizeof(wc.sta.ssid) - 1);
    if (password) strncpy((char *)wc.sta.password, password, sizeof(wc.sta.password) - 1);
    /* Accept open or WPA2 — an empty password network still associates. */
    wc.sta.threshold.authmode = (password && password[0]) ? WIFI_AUTH_WPA2_PSK
                                                           : WIFI_AUTH_OPEN;

    xEventGroupClearBits(s_sta_events, STA_CONNECTED_BIT | STA_FAIL_BIT);
    s_sta_retries = 0;
    s_sta_connecting = true;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
        s_sta_connecting = false;
        return err;
    }

    EventBits_t bits = xEventGroupWaitBits(
        s_sta_events, STA_CONNECTED_BIT | STA_FAIL_BIT, pdFALSE, pdFALSE,
        pdMS_TO_TICKS(timeout_ms > 0 ? timeout_ms : 30000));
    s_sta_connecting = false;

    return (bits & STA_CONNECTED_BIT) ? ESP_OK : ESP_FAIL;
}

/* ---- provisioning task ------------------------------------------------- */
static aktualino_portal_submit_t s_submit;   /* filled by /provision, read by task */

static void provision_task(void *arg)
{
    aktualino_portal_submit_t *sub = &s_submit;

    /* Persist Wi-Fi creds (SPEC §6.1) and, for Path B, the pasted credential, so
     * a reboot mid-flow resumes without the portal. */
    aktualino_store_save_wifi(sub->ssid, sub->password);
    if (sub->credential[0]) aktualino_store_save_prov_cred(sub->credential);

    aktualino_portal_set_state(AKT_PORTAL_JOINING_WIFI, sub->ssid);
    esp_err_t err = aktualino_portal_sta_connect(sub->ssid, sub->password, 30000);
    if (err != ESP_OK) {
        aktualino_portal_set_state(AKT_PORTAL_ERROR, "Wi-Fi join failed");
        s_submitted = false;
        vTaskDelete(NULL);
        return;
    }

    /* Hand off to the caller's backend enrolment driver (time sync, obtain
     * credential, ECU register, first manifest). It advances the remaining
     * states via aktualino_portal_set_state(). */
    if (s_cfg.provision) {
        err = s_cfg.provision(sub, s_cfg.user);
    } else {
        err = ESP_ERR_NOT_SUPPORTED;
    }

    if (err == ESP_OK) {
        aktualino_portal_set_state(AKT_PORTAL_DONE, NULL);
    } else if (s_state != AKT_PORTAL_ERROR) {
        aktualino_portal_set_state(AKT_PORTAL_ERROR, esp_err_to_name(err));
    }
    s_submitted = false;
    vTaskDelete(NULL);
}

/* ---- HTTP handlers ----------------------------------------------------- */
static esp_err_t root_get(httpd_req_t *req)
{
    size_t len = portal_html_gz_end - portal_html_gz_start;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, (const char *)portal_html_gz_start, len);
}

static esp_err_t config_get(httpd_req_t *req)
{
    const char *chip =
#if CONFIG_IDF_TARGET_ESP32S3
        "ESP32-S3";
#elif CONFIG_IDF_TARGET_ESP32
        "ESP32";
#else
        "ESP32";
#endif
    uint8_t mac[6] = { 0 };
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char devname[48];
    snprintf(devname, sizeof(devname), "%s-%02x%02x%02x",
             s_cfg.hardware_id ? s_cfg.hardware_id : "aktualino-esp32",
             mac[3], mac[4], mac[5]);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "ap_ssid", s_ap_ssid);
    cJSON_AddStringToObject(o, "chip", chip);
    cJSON_AddStringToObject(o, "backend_name",
                            s_cfg.backend_name ? s_cfg.backend_name : "Torizon Cloud");
    cJSON_AddStringToObject(o, "hardware_id",
                            s_cfg.hardware_id ? s_cfg.hardware_id : "aktualino-esp32");
    cJSON_AddStringToObject(o, "device_name", devname);
    cJSON_AddBoolToObject(o, "credential_needed", s_cfg.credential_needed);
    char *js = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, js ? js : "{}");
    free(js);
    return ESP_OK;
}

static esp_err_t scan_get(httpd_req_t *req)
{
    /* Blocking active scan; APSTA keeps the AP up (a brief off-channel hop). */
    wifi_scan_config_t sc = { .show_hidden = false };
    esp_err_t err = esp_wifi_scan_start(&sc, true);
    uint16_t n = 0;
    if (err == ESP_OK) esp_wifi_scan_get_ap_num(&n);
    if (n > 20) n = 20;

    cJSON *o = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(o, "networks");
    if (err == ESP_OK && n) {
        wifi_ap_record_t *recs = calloc(n, sizeof(*recs));
        if (recs) {
            uint16_t got = n;
            if (esp_wifi_scan_get_ap_records(&got, recs) == ESP_OK) {
                for (uint16_t i = 0; i < got; i++) {
                    if (recs[i].ssid[0] == '\0') continue;   /* skip hidden */
                    cJSON *net = cJSON_CreateObject();
                    cJSON_AddStringToObject(net, "ssid", (const char *)recs[i].ssid);
                    cJSON_AddNumberToObject(net, "rssi", recs[i].rssi);
                    cJSON_AddNumberToObject(net, "auth", recs[i].authmode);
                    cJSON_AddItemToArray(arr, net);
                }
            }
            free(recs);
        }
    }
    char *js = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, js ? js : "{\"networks\":[]}");
    free(js);
    return ESP_OK;
}

/* Copies o[k] into dst (empty string if the key is absent or not a string), and
 * returns false if the value does not fit. Callers must reject an overlong value
 * rather than store a clipped one: a truncated provisioning credential still
 * looks like a valid submission here and only surfaces much later, as an opaque
 * 401 from the backend's credential handshake. */
static bool json_copy_str(const cJSON *o, const char *k, char *dst, size_t cap)
{
    dst[0] = '\0';
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (cJSON_IsString(v) && v->valuestring) {
        if (strlen(v->valuestring) >= cap) return false;
        strcpy(dst, v->valuestring);
    }
    return true;
}

static esp_err_t provision_post(httpd_req_t *req)
{
    if (s_submitted) {
        httpd_resp_set_status(req, "409 Conflict");
        httpd_resp_sendstr(req,
            "{\"ok\":false,\"provisioning\":true,\"error\":\"already provisioning\"}");
        return ESP_OK;
    }
    int total = req->content_len;
    if (total <= 0 || total > 4096) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"request too large\"}");
        return ESP_OK;
    }
    char *buf = malloc(total + 1);
    if (!buf) return ESP_ERR_NO_MEM;
    int off = 0;
    while (off < total) {
        int r = httpd_req_recv(req, buf + off, total - off);
        if (r <= 0) { free(buf); return ESP_FAIL; }
        off += r;
    }
    buf[total] = '\0';

    cJSON *o = cJSON_Parse(buf);
    free(buf);
    if (!o) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"malformed request\"}");
        return ESP_OK;
    }
    const struct { const char *key; char *dst; size_t cap; } fields[] = {
        { "ssid",        s_submit.ssid,        sizeof(s_submit.ssid)        },
        { "password",    s_submit.password,    sizeof(s_submit.password)    },
        { "credential",  s_submit.credential,  sizeof(s_submit.credential)  },
        { "device_name", s_submit.device_name, sizeof(s_submit.device_name) },
    };
    memset(&s_submit, 0, sizeof(s_submit));
    const char *over = NULL;
    size_t over_max = 0;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!json_copy_str(o, fields[i].key, fields[i].dst, fields[i].cap)) {
            over = fields[i].key;
            over_max = fields[i].cap - 1;
            break;
        }
    }
    cJSON_Delete(o);

    if (over) {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "{\"ok\":false,\"error\":\"%s too long (max %u characters)\"}",
                 over, (unsigned)over_max);
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, msg);
        return ESP_OK;
    }

    if (!s_submit.ssid[0]) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ssid required\"}");
        return ESP_OK;
    }

    s_submitted = true;
    s_error[0] = '\0'; s_uuid[0] = '\0';
    aktualino_portal_set_state(AKT_PORTAL_JOINING_WIFI, s_submit.ssid);
    /* Provisioning runs off the httpd task so the response returns promptly and
     * the STA switch does not block the server. 6 KB stack: TLS + JSON. */
    if (xTaskCreate(provision_task, "akt_prov", 8192, NULL, 5, NULL) != pdPASS) {
        s_submitted = false;
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"could not start provisioning\"}");
        return ESP_OK;
    }
    httpd_resp_set_status(req, "202 Accepted");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t status_get(httpd_req_t *req)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "state", state_name(s_state));
    if (s_detail[0]) cJSON_AddStringToObject(o, "detail", s_detail);
    if (s_error[0])  cJSON_AddStringToObject(o, "error", s_error);
    if (s_uuid[0])   cJSON_AddStringToObject(o, "uuid", s_uuid);
    char *js = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_sendstr(req, js ? js : "{\"state\":\"idle\"}");
    free(js);
    return ESP_OK;
}

/* Captive-portal detection: phones probe well-known URLs; a 302 to the portal
 * root makes them auto-open the "Sign in to Wi-Fi network" sheet. Used as the
 * server's 404 handler so any unknown host/path is redirected too. */
static esp_err_t captive_redirect(httpd_req_t *req, httpd_err_code_t err)
{
    char loc[40];
    snprintf(loc, sizeof(loc), "http://%d.%d.%d.%d/",
             (int)(s_ap_ip & 0xff), (int)((s_ap_ip >> 8) & 0xff),
             (int)((s_ap_ip >> 16) & 0xff), (int)((s_ap_ip >> 24) & 0xff));
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", loc);
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static httpd_handle_t start_http(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.max_uri_handlers = 8;
    cfg.lru_purge_enable = true;
    cfg.stack_size = 6144;
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    /* The request-header buffer is sized by CONFIG_HTTPD_MAX_REQ_HDR_LEN
     * (raised to 2048 in sdkconfig.defaults): real phone browsers send a header
     * block larger than the 512 B default, which otherwise overflows and returns
     * HTTP 431 so the captive page fails to load. ESP-IDF 5.4 has no runtime
     * override for this, so it is a build-time Kconfig. */

    httpd_handle_t h = NULL;
    if (httpd_start(&h, &cfg) != ESP_OK) return NULL;

    httpd_uri_t routes[] = {
        { .uri = "/",           .method = HTTP_GET,  .handler = root_get },
        { .uri = "/config",     .method = HTTP_GET,  .handler = config_get },
        { .uri = "/scan",       .method = HTTP_GET,  .handler = scan_get },
        { .uri = "/status",     .method = HTTP_GET,  .handler = status_get },
        { .uri = "/provision",  .method = HTTP_POST, .handler = provision_post },
    };
    for (size_t i = 0; i < sizeof(routes)/sizeof(routes[0]); i++)
        httpd_register_uri_handler(h, &routes[i]);
    /* Everything else (captive probes, wrong host) -> redirect to the portal. */
    httpd_register_err_handler(h, HTTPD_404_NOT_FOUND, captive_redirect);
    return h;
}

/* ---- captive DNS: answer every A query with the AP IP ------------------ */
static void dns_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { ESP_LOGE(TAG, "DNS socket failed"); vTaskDelete(NULL); return; }
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53),
                              .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        ESP_LOGE(TAG, "DNS bind :53 failed"); close(sock); vTaskDelete(NULL); return;
    }
    ESP_LOGI(TAG, "captive DNS up on :53 -> " IPSTR, IP2STR((esp_ip4_addr_t *)&s_ap_ip));

    uint8_t pkt[512];
    for (;;) {
        struct sockaddr_in from; socklen_t fl = sizeof(from);
        int n = recvfrom(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&from, &fl);
        if (n < 12) continue;                     /* smaller than a DNS header */

        /* Turn the query into an answer that resolves the queried name to the
         * AP IP: set QR + a single A answer using a name-compression pointer to
         * the question (0xC00C). Only the first question is answered. */
        pkt[2] |= 0x80;               /* QR = response */
        pkt[3] = 0x00;                /* RCODE = 0, not authoritative/truncated */
        pkt[6] = 0x00; pkt[7] = 0x01; /* ANCOUNT = 1 */
        pkt[8] = 0; pkt[9] = 0;       /* NSCOUNT = 0 */
        pkt[10] = 0; pkt[11] = 0;     /* ARCOUNT = 0 */

        if (n + 16 > (int)sizeof(pkt)) continue;
        uint8_t *a = pkt + n;
        *a++ = 0xC0; *a++ = 0x0C;                 /* name -> offset 12 (question) */
        *a++ = 0x00; *a++ = 0x01;                 /* TYPE  A */
        *a++ = 0x00; *a++ = 0x01;                 /* CLASS IN */
        *a++ = 0x00; *a++ = 0x00; *a++ = 0x00; *a++ = 0x3C;  /* TTL 60s */
        *a++ = 0x00; *a++ = 0x04;                 /* RDLENGTH 4 */
        memcpy(a, &s_ap_ip, 4); a += 4;           /* RDATA = AP IP */

        sendto(sock, pkt, a - pkt, 0, (struct sockaddr *)&from, fl);
    }
}

/* ---- start ------------------------------------------------------------- */
esp_err_t aktualino_portal_start(const aktualino_portal_cfg_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    s_cfg = *cfg;

    /* Device-unique SSID from the last 3 bytes of the factory MAC. */
    uint8_t mac[6] = { 0 };
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(s_ap_ssid, sizeof(s_ap_ssid), "aktualino-%02x%02x%02x",
             mac[3], mac[4], mac[5]);

    s_sta_events = xEventGroupCreate();
    if (!s_sta_events) return ESP_ERR_NO_MEM;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wcfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &on_wifi_event, NULL, NULL));

    wifi_config_t apc = { 0 };
    strncpy((char *)apc.ap.ssid, s_ap_ssid, sizeof(apc.ap.ssid) - 1);
    apc.ap.ssid_len = strlen(s_ap_ssid);
    apc.ap.channel = 1;
    apc.ap.max_connection = 4;
    apc.ap.authmode = WIFI_AUTH_OPEN;   /* TODO(security): WPA2 + PoP (SPEC §6.1) */

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &apc));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* AP IP (default 192.168.4.1) for captive DNS + redirects. */
    esp_netif_ip_info_t ip;
    if (ap_netif && esp_netif_get_ip_info(ap_netif, &ip) == ESP_OK) {
        s_ap_ip = ip.ip.addr;
    } else {
        s_ap_ip = htonl(0xC0A80401);   /* 192.168.4.1 fallback */
    }

    if (!start_http()) { ESP_LOGE(TAG, "HTTP server failed to start"); return ESP_FAIL; }
    xTaskCreate(dns_task, "akt_dns", 3072, NULL, 5, NULL);

    ESP_LOGW(TAG, "==================================================");
    ESP_LOGW(TAG, " SETUP PORTAL UP — join open Wi-Fi \"%s\"", s_ap_ssid);
    ESP_LOGW(TAG, " then open http://%d.%d.%d.%d/ (captive page auto-opens)",
             (int)(s_ap_ip & 0xff), (int)((s_ap_ip >> 8) & 0xff),
             (int)((s_ap_ip >> 16) & 0xff), (int)((s_ap_ip >> 24) & 0xff));
    ESP_LOGW(TAG, "==================================================");
    return ESP_OK;
}
