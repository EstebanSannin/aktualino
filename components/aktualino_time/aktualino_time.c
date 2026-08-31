#include "aktualino_time.h"

#include <string.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_sntp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "akt_time";

#ifdef CONFIG_AKTUALINO_SNTP_SERVER
#define DEFAULT_SNTP_SERVER CONFIG_AKTUALINO_SNTP_SERVER
#else
#define DEFAULT_SNTP_SERVER "pool.ntp.org"
#endif

bool aktualino_time_is_valid(void)
{
    time_t now = time(NULL);
    return now >= (time_t)AKTUALINO_TIME_FLOOR_EPOCH;
}

char *aktualino_time_iso8601(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    return buf;
}

esp_err_t aktualino_time_sync(const char *server, uint32_t timeout_ms)
{
    const char *ntp = (server && server[0]) ? server : DEFAULT_SNTP_SERVER;

    if (esp_sntp_enabled()) {
        esp_sntp_stop();
    }
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, ntp);
    sntp_set_sync_mode(SNTP_SYNC_MODE_IMMED);
    esp_sntp_init();

    ESP_LOGI(TAG, "SNTP started (server=%s), waiting up to %u ms for time",
             ntp, (unsigned)timeout_ms);

    const TickType_t step = pdMS_TO_TICKS(200);
    TickType_t waited = 0;
    const TickType_t limit = pdMS_TO_TICKS(timeout_ms);
    while (!aktualino_time_is_valid() && waited < limit) {
        vTaskDelay(step);
        waited += step;
    }

    if (!aktualino_time_is_valid()) {
        ESP_LOGW(TAG, "SNTP did not sync within %u ms", (unsigned)timeout_ms);
        return ESP_ERR_TIMEOUT;
    }

    char iso[25];
    ESP_LOGI(TAG, "time synced: %s", aktualino_time_iso8601(iso, sizeof(iso)));
    return ESP_OK;
}
