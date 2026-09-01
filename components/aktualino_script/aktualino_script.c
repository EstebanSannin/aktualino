/*
 * aktualino_script.c — Berry script secondary: install + run + report.
 * See aktualino_script.h.
 *
 * Runtime model: the installed bundle runs in ONE long-lived VM ("live"), and a
 * dedicated low-priority FreeRTOS task ticks its loop() every SCRIPT_TICK_MS, so
 * scripts run continuously (not just once at boot). setup() runs once when a
 * bundle becomes live. A new bundle is validated (compile + setup() + a few
 * loop()s without error), stored verbatim in the `scripts` partition, then
 * swapped in as the new live VM (the previous live VM is only replaced once the
 * new one validates — a lightweight keep-last-good). After SCRIPT_MAX_FAULTS
 * consecutive loop() errors the bundle is quarantined (loop() stops; VM kept).
 *
 * MVP scope (S3): storage is a raw single "current" slot (LittleFS + KV + a
 * previous slot are S4/S5); the install-success gate is load+setup+first-loops
 * (the health_ok() heartbeat is logged, not required, until S4); there is no
 * capability allowlist yet (full host API), only a flash-pin guard so a demo
 * script cannot brick the board. Per-loop CPU budget is S4.
 */
#include "sdkconfig.h"
#if CONFIG_AKTUALINO_SCRIPT_SECONDARY   /* whole file is empty when the feature is off */

#include "aktualino_script.h"

#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "mbedtls/sha256.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "aktualino_core.h"
#include "aktualino_net.h"
#include "aktualino_store.h"
#include "aktualino_prov.h"
#include "aktualino_berry.h"

static const char *TAG = "akt_script";

#define SCRIPT_TICK_MS   500     /* loop() cadence for the live bundle */
#define SCRIPT_MAX_FAULTS 3      /* consecutive loop() errors -> quarantine (spec §8) */

#define BUNDLE_MAGIC   0xAB71B0DEu
#define HDR_OFFSET     0x0000
#define BUNDLE_OFFSET  0x1000            /* bundle bytes start after the header sector */
#define MAX_BUNDLE     (128 * 1024)      /* generous cap for a script bundle */

typedef struct {
    uint32_t magic;
    uint32_t length;
    uint8_t  sha256[32];
    char     filepath[254];
} bundle_hdr_t;

static const esp_partition_t *s_part;    /* the `scripts` data partition */

/* ------------------------------------------------------------------ store */

static const esp_partition_t *find_scripts_part(void)
{
    return esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                    ESP_PARTITION_SUBTYPE_DATA_SPIFFS, "scripts");
}

/* Read the stored bundle header. Returns true if a valid bundle is present. */
static bool store_header(bundle_hdr_t *out)
{
    if (!s_part) return false;
    if (esp_partition_read(s_part, HDR_OFFSET, out, sizeof(*out)) != ESP_OK)
        return false;
    return out->magic == BUNDLE_MAGIC && out->length > 0 && out->length <= MAX_BUNDLE;
}

/* Persist a verified bundle verbatim: bytes then header (header last = commit). */
static esp_err_t store_write(const char *filepath, const uint8_t sha[32],
                             const uint8_t *buf, size_t len)
{
    if (!s_part || len == 0 || len > MAX_BUNDLE) return ESP_ERR_INVALID_ARG;
    size_t erase = BUNDLE_OFFSET + ((len + 4095) & ~4095u);
    esp_err_t err = esp_partition_erase_range(s_part, 0, erase);
    if (err != ESP_OK) return err;
    err = esp_partition_write(s_part, BUNDLE_OFFSET, buf, len);
    if (err != ESP_OK) return err;
    bundle_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = BUNDLE_MAGIC;
    h.length = (uint32_t)len;
    memcpy(h.sha256, sha, 32);
    strncpy(h.filepath, filepath ? filepath : "", sizeof(h.filepath) - 1);
    return esp_partition_write(s_part, HDR_OFFSET, &h, sizeof(h));  /* commit */
}

/* Read the stored bundle bytes into a freshly malloc'd buffer (caller frees). */
static uint8_t *store_read(size_t *out_len)
{
    bundle_hdr_t h;
    if (!store_header(&h)) return NULL;
    uint8_t *buf = malloc(h.length);
    if (!buf) return NULL;
    if (esp_partition_read(s_part, BUNDLE_OFFSET, buf, h.length) != ESP_OK) {
        free(buf); return NULL;
    }
    if (out_len) *out_len = h.length;
    return buf;
}

/* -------------------------------------------------------- Berry host API */

static volatile int s_health_ok;

/* Flash-pin guard (brick-prevention, not a full allowlist — that is S4/S5): a
 * script must never drive the SPI-flash pins. Conservative bounds cover both
 * targets; refuse GPIO 6-11 (classic flash) and out-of-range. */
static bool pin_ok(bint pin)
{
    if (pin < 0 || pin > 48) return false;
    if (pin >= 6 && pin <= 11) return false;   /* SPI flash — never touch */
    return true;
}

static int l_log(bvm *vm) {
    ESP_LOGI("bundle", "%s", be_top(vm) >= 1 ? be_tostring(vm, 1) : "");
    be_return_nil(vm);
}
static int l_report(bvm *vm) {
    int t = be_top(vm);
    const char *n = (t >= 1) ? be_tostring(vm, 1) : "?";
    long long v = (t >= 2 && be_isint(vm, 2)) ? (long long)be_toint(vm, 2) : 0;
    ESP_LOGI("bundle", "report %s=%lld", n, v);       /* telemetry uplink is future */
    be_return_nil(vm);
}
static int l_health_ok(bvm *vm) { s_health_ok = 1; be_return_nil(vm); }

static int l_gpio_mode(bvm *vm) {
    if (be_top(vm) >= 2 && be_isint(vm, 1) && be_isint(vm, 2)) {
        bint pin = be_toint(vm, 1), m = be_toint(vm, 2);
        if (pin_ok(pin)) {
            gpio_reset_pin((gpio_num_t)pin);
            gpio_set_direction((gpio_num_t)pin, m == 1 ? GPIO_MODE_OUTPUT : GPIO_MODE_INPUT);
            if (m == 2) gpio_set_pull_mode((gpio_num_t)pin, GPIO_PULLUP_ONLY);
        } else ESP_LOGW("bundle", "gpio_mode refused pin %lld", (long long)pin);
    }
    be_return_nil(vm);
}
static int l_gpio_set(bvm *vm) {
    if (be_top(vm) >= 2 && be_isint(vm, 1) && be_isint(vm, 2)) {
        bint pin = be_toint(vm, 1), lvl = be_toint(vm, 2);
        if (pin_ok(pin)) {
            gpio_set_direction((gpio_num_t)pin, GPIO_MODE_OUTPUT);
            gpio_set_level((gpio_num_t)pin, lvl ? 1 : 0);
        } else ESP_LOGW("bundle", "gpio_set refused pin %lld", (long long)pin);
    }
    be_return_nil(vm);
}
static int l_gpio_get(bvm *vm) {
    bint pin = (be_top(vm) >= 1 && be_isint(vm, 1)) ? be_toint(vm, 1) : -1;
    be_pushint(vm, pin_ok(pin) ? gpio_get_level((gpio_num_t)pin) : 0);
    be_return(vm);
}
static int l_millis(bvm *vm) {
    be_pushint(vm, (bint)(esp_timer_get_time() / 1000));   /* ms since boot */
    be_return(vm);
}

static void register_api(akt_berry_t *rt)
{
    akt_berry_register(rt, "log",       l_log);
    akt_berry_register(rt, "report",    l_report);
    akt_berry_register(rt, "health_ok", l_health_ok);
    akt_berry_register(rt, "gpio_mode", l_gpio_mode);
    akt_berry_register(rt, "gpio_set",  l_gpio_set);
    akt_berry_register(rt, "gpio_get",  l_gpio_get);
    akt_berry_register(rt, "millis",    l_millis);
}

/*
 * Validate a bundle: compile + setup() + the first `loops` loop() cycles without
 * error. On success returns a LIVE VM (setup already run) the caller promotes via
 * set_live(); on failure frees it and returns NULL. Sets *health = did health_ok().
 */
static akt_berry_t *validate_bundle(const uint8_t *buf, size_t len, int loops, bool *health)
{
    s_health_ok = 0;
    akt_berry_t *rt = akt_berry_new();
    if (!rt) { ESP_LOGE(TAG, "berry: vm alloc failed"); return NULL; }
    register_api(rt);
    if (akt_berry_load(rt, "bundle", buf, len) != 0) {
        ESP_LOGE(TAG, "bundle load failed: %s", akt_berry_last_error(rt));
        akt_berry_free(rt); return NULL;
    }
    if (akt_berry_call(rt, "setup") == AKT_BERRY_ERROR) {
        ESP_LOGE(TAG, "bundle setup() error: %s", akt_berry_last_error(rt));
        akt_berry_free(rt); return NULL;
    }
    for (int i = 0; i < loops; i++) {
        if (akt_berry_call(rt, "loop") == AKT_BERRY_ERROR) {
            ESP_LOGE(TAG, "bundle loop() error: %s", akt_berry_last_error(rt));
            akt_berry_free(rt); return NULL;
        }
    }
    if (health) *health = s_health_ok;
    return rt;
}

/* ------------------------------------------------------ live VM + scheduler */

static akt_berry_t     *s_rt;          /* the currently-running bundle's VM */
static SemaphoreHandle_t s_lock;       /* guards s_rt / faults across tasks  */
static int              s_faults;      /* consecutive loop() faults          */
static bool             s_quarantined; /* loop() stopped after too many faults */

/* Promote a validated VM to live, freeing the previous one (keep-last-good:
 * the old bundle keeps running until the new one validates). */
static void set_live(akt_berry_t *rt)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_rt) akt_berry_free(s_rt);
    s_rt = rt;
    s_faults = 0;
    s_quarantined = false;
    xSemaphoreGive(s_lock);
}

/* Dedicated task: tick the live bundle's loop() every SCRIPT_TICK_MS. */
static void script_task(void *arg)
{
    (void)arg;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(SCRIPT_TICK_MS));
        xSemaphoreTake(s_lock, portMAX_DELAY);
        if (s_rt && !s_quarantined) {
            if (akt_berry_call(s_rt, "loop") == AKT_BERRY_ERROR) {
                ESP_LOGE(TAG, "loop() error: %s", akt_berry_last_error(s_rt));
                if (++s_faults >= SCRIPT_MAX_FAULTS) {
                    s_quarantined = true;
                    ESP_LOGE(TAG, "bundle QUARANTINED after %d loop() faults — "
                                  "loop() stopped (VM kept)", SCRIPT_MAX_FAULTS);
                }
            } else {
                s_faults = 0;
            }
        }
        xSemaphoreGive(s_lock);
    }
}

/* --------------------------------------------------------------- download */

typedef struct { uint8_t *buf; size_t cap; size_t len; } ram_sink_t;

static esp_err_t ram_sink_cb(const void *data, size_t len, void *user)
{
    ram_sink_t *s = user;
    if (s->len + len > s->cap) return ESP_ERR_INVALID_SIZE;
    memcpy(s->buf + s->len, data, len);
    s->len += len;
    return ESP_OK;
}

/* Download the assigned bundle into RAM and verify sha256 + length. */
static esp_err_t download_verify(const aktualino_poll_result_t *res,
                                 uint8_t **out_buf, size_t *out_len)
{
    if (res->target_length == 0 || res->target_length > MAX_BUNDLE)
        return ESP_ERR_INVALID_SIZE;

    aktualino_creds_t creds;
    esp_err_t err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) return err;

    uint8_t *buf = heap_caps_malloc(res->target_length, MALLOC_CAP_SPIRAM);
    if (!buf) buf = malloc(res->target_length);
    if (!buf) { aktualino_store_free_creds(&creds); return ESP_ERR_NO_MEM; }

    char url[400];
    snprintf(url, sizeof(url), "%s/repo/targets/%s", creds.gateway_url, res->target_path);
    ESP_LOGW(TAG, "DOWNLOAD bundle: GET %s (len=%zu)", url, res->target_length);

    ram_sink_t sink = { .buf = buf, .cap = res->target_length, .len = 0 };
    aktualino_net_get_cfg_t cfg = {
        .url = url, .cacert_pem = creds.cacert_pem,
        .client_cert_pem = creds.client_cert_pem,
        .client_key_pem = creds.client_key_pem, .timeout_ms = 60000,
    };
    int status = 0; size_t got = 0;
    err = aktualino_net_get_stream(&cfg, ram_sink_cb, &sink, &status, &got);
    aktualino_store_free_creds(&creds);
    if (err != ESP_OK || status != 200) {
        ESP_LOGE(TAG, "bundle download failed (err=%s http=%d)", esp_err_to_name(err), status);
        free(buf); return (err != ESP_OK) ? err : ESP_FAIL;
    }
    if (got != res->target_length) {
        ESP_LOGE(TAG, "bundle LENGTH MISMATCH got=%zu want=%zu", got, res->target_length);
        free(buf); return ESP_ERR_INVALID_SIZE;
    }
    uint8_t digest[32];
    mbedtls_sha256(buf, got, digest, 0);
    if (memcmp(digest, res->target_sha256, 32) != 0) {
        ESP_LOGE(TAG, "bundle SHA-256 MISMATCH — refusing");
        free(buf); return ESP_ERR_INVALID_CRC;
    }
    *out_buf = buf; *out_len = got;
    return ESP_OK;
}

/* ------------------------------------------------------------------ public */

esp_err_t aktualino_script_init(void)
{
    s_part = find_scripts_part();
    if (!s_part) {
        ESP_LOGW(TAG, "no `scripts` partition — script secondary storage disabled");
        return ESP_ERR_NOT_FOUND;
    }
    ESP_LOGI(TAG, "scripts partition @0x%06lx size %lu KB",
             (unsigned long)s_part->address, (unsigned long)(s_part->size / 1024));
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) return ESP_ERR_NO_MEM;

    /* Activate any already-installed bundle as the live VM. */
    size_t len = 0;
    uint8_t *buf = store_read(&len);
    if (buf) {
        bool health = false;
        akt_berry_t *rt = validate_bundle(buf, len, 1, &health);
        free(buf);
        if (rt) {
            set_live(rt);
            ESP_LOGI(TAG, "stored bundle is LIVE (%zu B)%s", len, health ? " +health" : "");
        } else {
            ESP_LOGE(TAG, "stored bundle failed to load — not running it");
        }
    } else {
        ESP_LOGI(TAG, "no bundle installed yet");
    }

    /* Start the scheduler that ticks loop() continuously. */
    xTaskCreate(script_task, "akt_script", 8192, NULL, 3, NULL);
    return ESP_OK;
}

esp_err_t aktualino_script_poll(int64_t now)
{
    if (!s_part) return ESP_OK;   /* no storage -> nothing to do */

    aktualino_poll_result_t res;
    esp_err_t err = aktualino_core_poll_director(AKT_SCRIPT_HWID, now, &res);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "secondary poll failed: %s", esp_err_to_name(err));
        return err;
    }
    if (!res.target_assigned) {
        ESP_LOGI(TAG, "no bundle assigned for %s", AKT_SCRIPT_HWID);
        return ESP_OK;
    }

    /* Is this the bundle we already have installed? */
    bundle_hdr_t cur;
    bool have = store_header(&cur);
    bool same = have && (memcmp(cur.sha256, res.target_sha256, 32) == 0);

    const char *corr = res.correlation_id[0] ? res.correlation_id : NULL;

    if (same) {
        ESP_LOGI(TAG, "bundle %s already installed — re-reporting success", res.target_path);
        return aktualino_prov_report_secondary(res.target_path, res.target_sha256,
                                               res.target_length, corr, true);
    }

    ESP_LOGW(TAG, "new bundle assigned: %s (v?, len=%zu) — cross-verify + install",
             res.target_path, res.target_length);

    /* THE TWO-REPO GATE: the Image repo must independently sign this exact target. */
    err = aktualino_core_crosscheck_target(&res, now);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "bundle cross-repo verify REFUSED — reporting failure");
        aktualino_prov_report_secondary(res.target_path, res.target_sha256,
                                        res.target_length, corr, false);
        return err;
    }

    uint8_t *buf = NULL; size_t len = 0;
    err = download_verify(&res, &buf, &len);
    if (err != ESP_OK) {
        aktualino_prov_report_secondary(res.target_path, res.target_sha256,
                                        res.target_length, corr, false);
        return err;
    }

    /* Validate (MVP gate: loads + setup + first loops without error). The
     * validated VM becomes live only after we commit to flash below. */
    bool health = false;
    akt_berry_t *rt = validate_bundle(buf, len, 5, &health);
    if (!rt) {
        ESP_LOGE(TAG, "bundle failed to run — NOT installing; reporting failure");
        free(buf);
        aktualino_prov_report_secondary(res.target_path, res.target_sha256,
                                        res.target_length, corr, false);
        return ESP_FAIL;
    }

    /* Commit to flash, then swap in the new bundle as the live VM. */
    err = store_write(res.target_path, res.target_sha256, buf, len);
    free(buf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "bundle store_write failed: %s", esp_err_to_name(err));
        akt_berry_free(rt);
        aktualino_prov_report_secondary(res.target_path, res.target_sha256,
                                        res.target_length, corr, false);
        return err;
    }
    set_live(rt);   /* the new bundle now runs continuously via the scheduler */
    ESP_LOGW(TAG, "BUNDLE INSTALLED + LIVE: %s (%zu B, health=%d) — reporting success",
             res.target_path, len, health);
    return aktualino_prov_report_secondary(res.target_path, res.target_sha256,
                                           res.target_length, corr, true);
}

#endif /* CONFIG_AKTUALINO_SCRIPT_SECONDARY */
