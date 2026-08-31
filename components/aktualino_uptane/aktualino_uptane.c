/*
 * aktualino_uptane.c — ESP component wrapper over the portable akt_uptane core.
 * All logic is in akt_uptane.c (host-unit-tested); this file adapts to esp_err_t
 * and the void*-cJSON on-target surface.
 */
#include "aktualino_uptane.h"
#include "akt_uptane.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cJSON.h"

static esp_err_t map_err(int rc)
{
    switch (rc) {
        case AKT_OK:            return ESP_OK;
        case AKT_ERR_PARSE:     return ESP_ERR_INVALID_ARG;
        case AKT_ERR_NO_ROLE:   return ESP_ERR_NOT_FOUND;
        case AKT_ERR_THRESHOLD: return ESP_ERR_INVALID_CRC;
        case AKT_ERR_EXPIRED:   return ESP_ERR_TIMEOUT;
        case AKT_ERR_ROLLBACK:  return ESP_ERR_INVALID_VERSION;
        case AKT_ERR_NO_TARGET: return ESP_ERR_NOT_FOUND;
        default:                return ESP_FAIL;
    }
}

esp_err_t aktualino_uptane_canonical_json(const void *cjson_obj,
                                          char *out, size_t cap, size_t *out_len)
{
    if (!cjson_obj || !out) return ESP_ERR_INVALID_ARG;
    size_t n = 0;
    char *canon = akt_canonical_json((const cJSON *)cjson_obj, &n);
    if (!canon) return ESP_FAIL;
    esp_err_t err = ESP_OK;
    if (n + 1 > cap) {
        err = ESP_ERR_INVALID_SIZE;
    } else {
        memcpy(out, canon, n + 1);
        if (out_len) *out_len = n;
    }
    free(canon);
    return err;
}

esp_err_t aktualino_uptane_verify_role(const void *root_signed_cjson,
                                       const char *role_name,
                                       const void *envelope_cjson,
                                       int64_t now, int32_t min_version)
{
    int rc = akt_verify_role((const cJSON *)root_signed_cjson, role_name,
                             (const cJSON *)envelope_cjson,
                             (time_t)now, (long)min_version);
    return map_err(rc);
}

esp_err_t aktualino_uptane_select_target(const void *targets_signed_cjson,
                                         const char *hwid,
                                         aktualino_target_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    akt_target_t t;
    int rc = akt_select_target((const cJSON *)targets_signed_cjson, hwid, &t);
    if (rc != AKT_OK) return map_err(rc);
    memset(out, 0, sizeof(*out));
    snprintf(out->filepath, sizeof(out->filepath), "%s", t.filepath);
    memcpy(out->sha256, t.sha256, 32);
    out->length = t.length;
    out->version = (int32_t)t.version;
    return ESP_OK;
}

esp_err_t aktualino_uptane_build_manifest(const char *primary_ecu_serial,
                                          const aktualino_target_t *installed,
                                          const char *attacks_detected,
                                          const uint8_t ecu_pk[32],
                                          const uint8_t ecu_sk[64],
                                          char *out, size_t cap, size_t *out_len)
{
    if (!installed || !out) return ESP_ERR_INVALID_ARG;
    akt_target_t t;
    memset(&t, 0, sizeof(t));
    snprintf(t.filepath, sizeof(t.filepath), "%s", installed->filepath);
    memcpy(t.sha256, installed->sha256, 32);
    t.length = installed->length;
    t.version = installed->version;

    size_t n = 0;
    char *json = akt_build_manifest(primary_ecu_serial, &t, attacks_detected,
                                    ecu_pk, ecu_sk, &n);
    if (!json) return ESP_FAIL;
    esp_err_t err = ESP_OK;
    if (n + 1 > cap) {
        err = ESP_ERR_INVALID_SIZE;
    } else {
        memcpy(out, json, n + 1);
        if (out_len) *out_len = n;
    }
    free(json);
    return err;
}
