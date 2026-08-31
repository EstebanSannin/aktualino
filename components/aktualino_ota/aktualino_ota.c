#include "aktualino_ota.h"

#include <inttypes.h>
#include <string.h>

#include "esp_log.h"

static const char *TAG = "akt_ota";

esp_err_t aktualino_ota_begin(aktualino_ota_ctx_t *ctx, size_t image_size)
{
    if (!ctx) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(ctx, 0, sizeof(*ctx));

    const esp_partition_t *target = esp_ota_get_next_update_partition(NULL);
    if (!target) {
        ESP_LOGE(TAG, "no inactive OTA partition available");
        return ESP_ERR_NOT_FOUND;
    }
    ESP_LOGI(TAG, "OTA target slot: %s @ 0x%08" PRIx32 " (size 0x%08" PRIx32 ")",
             target->label, target->address, target->size);

    mbedtls_sha256_init(&ctx->sha);
    /* 0 = SHA-256 (not SHA-224). */
    int rc = mbedtls_sha256_starts(&ctx->sha, 0);
    if (rc != 0) {
        ESP_LOGE(TAG, "sha256_starts failed: -0x%04x", -rc);
        mbedtls_sha256_free(&ctx->sha);
        return ESP_FAIL;
    }

    esp_err_t err = esp_ota_begin(target,
                                  image_size ? image_size : OTA_SIZE_UNKNOWN,
                                  &ctx->handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        mbedtls_sha256_free(&ctx->sha);
        return err;
    }

    ctx->partition = target;
    ctx->written = 0;
    ctx->active = true;
    return ESP_OK;
}

esp_err_t aktualino_ota_write(aktualino_ota_ctx_t *ctx,
                              const void *data, size_t len)
{
    if (!ctx || !ctx->active || (!data && len)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return ESP_OK;
    }

    esp_err_t err = esp_ota_write(ctx->handle, data, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_write failed at %zu: %s",
                 ctx->written, esp_err_to_name(err));
        return err;
    }

    int rc = mbedtls_sha256_update(&ctx->sha, (const unsigned char *)data, len);
    if (rc != 0) {
        ESP_LOGE(TAG, "sha256_update failed: -0x%04x", -rc);
        return ESP_FAIL;
    }

    ctx->written += len;
    return ESP_OK;
}

esp_err_t aktualino_ota_end(aktualino_ota_ctx_t *ctx, uint8_t out_sha256[32])
{
    if (!ctx || !ctx->active) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t digest[32];
    int rc = mbedtls_sha256_finish(&ctx->sha, digest);
    mbedtls_sha256_free(&ctx->sha);
    if (rc != 0) {
        ESP_LOGE(TAG, "sha256_finish failed: -0x%04x", -rc);
        esp_ota_abort(ctx->handle);
        ctx->active = false;
        return ESP_FAIL;
    }

    esp_err_t err = esp_ota_end(ctx->handle);
    ctx->active = false;
    if (err != ESP_OK) {
        /* Includes ESP_ERR_OTA_VALIDATE_FAILED if the image header is bad. */
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        return err;
    }

    if (out_sha256) {
        memcpy(out_sha256, digest, sizeof(digest));
    }
    ESP_LOGI(TAG, "OTA write complete: %zu bytes hashed", ctx->written);
    return ESP_OK;
}

esp_err_t aktualino_ota_set_boot(aktualino_ota_ctx_t *ctx)
{
    if (!ctx || !ctx->partition) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = esp_ota_set_boot_partition(ctx->partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s",
                 esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "boot partition set to %s; reboot to activate",
             ctx->partition->label);
    return ESP_OK;
}

void aktualino_ota_abort(aktualino_ota_ctx_t *ctx)
{
    if (!ctx || !ctx->active) {
        return;
    }
    esp_ota_abort(ctx->handle);
    mbedtls_sha256_free(&ctx->sha);
    ctx->active = false;
    ESP_LOGW(TAG, "OTA session aborted after %zu bytes", ctx->written);
}

esp_err_t aktualino_ota_mark_valid(void)
{
    esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "running image marked valid; rollback cancelled");
    } else {
        ESP_LOGE(TAG, "mark_app_valid failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t aktualino_ota_rollback(void)
{
    ESP_LOGW(TAG, "rolling back: marking running image invalid and rebooting");
    /* Does not return on success. */
    return esp_ota_mark_app_invalid_rollback_and_reboot();
}

esp_err_t aktualino_ota_running_info(bool *out_pending_verify)
{
    if (out_pending_verify) {
        *out_pending_verify = false;
    }

    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running) {
        ESP_LOGE(TAG, "esp_ota_get_running_partition returned NULL");
        return ESP_FAIL;
    }

    const char *state_str = "n/a";
    esp_ota_img_states_t state;
    if (esp_ota_get_state_partition(running, &state) == ESP_OK) {
        switch (state) {
        case ESP_OTA_IMG_NEW:            state_str = "NEW"; break;
        case ESP_OTA_IMG_PENDING_VERIFY: state_str = "PENDING_VERIFY"; break;
        case ESP_OTA_IMG_VALID:          state_str = "VALID"; break;
        case ESP_OTA_IMG_INVALID:        state_str = "INVALID"; break;
        case ESP_OTA_IMG_ABORTED:        state_str = "ABORTED"; break;
        case ESP_OTA_IMG_UNDEFINED:      state_str = "UNDEFINED"; break;
        default:                         state_str = "?"; break;
        }
        if (out_pending_verify) {
            *out_pending_verify = (state == ESP_OTA_IMG_PENDING_VERIFY);
        }
    }

    ESP_LOGI(TAG, "running partition: %s @ 0x%08" PRIx32
                  " subtype 0x%02x  ota-state=%s",
             running->label, running->address, running->subtype, state_str);
    return ESP_OK;
}

esp_err_t aktualino_ota_inactive_slot_failed(bool *out)
{
    if (out) *out = false;
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    if (!next) return ESP_ERR_NOT_FOUND;
    esp_ota_img_states_t state;
    if (esp_ota_get_state_partition(next, &state) != ESP_OK) {
        /* No otadata entry for the slot yet — treat as "not failed". */
        return ESP_OK;
    }
    bool failed = (state == ESP_OTA_IMG_INVALID || state == ESP_OTA_IMG_ABORTED);
    if (out) *out = failed;
    ESP_LOGI(TAG, "inactive slot %s ota-state=%d (%s)", next->label, state,
             failed ? "FAILED/rolled-back" : "ok");
    return ESP_OK;
}
