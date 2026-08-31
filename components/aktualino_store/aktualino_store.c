/*
 * aktualino_store — NVS-backed credential + ECU-key + TUF-metadata store (T1.5).
 *
 * Two NVS namespaces in the default `nvs` partition:
 *   NS_ID  ("akt_id")  — device identity: uuid, gateway URL, mTLS cert/key,
 *                        pinned server CA, primary ECU serial, the on-device
 *                        Ed25519 ECU keypair, and a `provisioned` flag.
 *   NS_TUF ("akt_tuf") — TUF metadata blobs keyed by a sanitized name.
 *
 * MVP is plaintext NVS; encrypted NVS (flash-encryption + NVS keys) drops in
 * behind this same API in the hardening phase (SPEC §8). The credential PEMs
 * are a few KB each — well within NVS variable-length-entry limits.
 */
#include "aktualino_store.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "akt_store";

#define NS_ID  "akt_id"
#define NS_TUF "akt_tuf"

/* NVS key names (<= 15 chars). */
#define K_UUID   "uuid"
#define K_GWURL  "gw_url"
#define K_CERT   "cert"
#define K_PKEY   "pkey"
#define K_CACERT "cacert"
#define K_ECUSER "ecu_ser"
#define K_ECUPK  "ecu_pk"
#define K_ECUSK  "ecu_sk"
#define K_PROV   "prov"
#define K_NONCE  "id_nonce"
/* Wi-Fi station credentials + Path-B provisioning credential (SPEC §6.1). */
#define K_WIFISSID "wifi_ssid"
#define K_WIFIPASS "wifi_pass"
#define K_PROVCRED "prov_cred"
/* Install state (Phase 3). Running image = confirmed installed Director target. */
#define K_RUNFP  "run_fp"
#define K_RUNSHA "run_sha"
#define K_RUNLEN "run_len"
/* Pending update = downloaded + set-boot, awaiting post-reboot confirmation. */
#define K_PNDFP  "pnd_fp"
#define K_PNDSHA "pnd_sha"
#define K_PNDLEN "pnd_len"
#define K_PNDCID "pnd_cid"

/* ------------------------------------------------------------------ */
esp_err_t aktualino_store_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "erasing NVS (no free pages / new version)");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

/* ---- small helpers ------------------------------------------------ */
/* malloc a copy of an NVS string value; *out set to a fresh buffer or NULL. */
static esp_err_t get_str_dup(nvs_handle_t h, const char *key, char **out)
{
    *out = NULL;
    size_t len = 0;
    esp_err_t err = nvs_get_str(h, key, NULL, &len);
    if (err != ESP_OK) return err;
    char *buf = malloc(len);
    if (!buf) return ESP_ERR_NO_MEM;
    err = nvs_get_str(h, key, buf, &len);
    if (err != ESP_OK) { free(buf); return err; }
    *out = buf;
    return ESP_OK;
}

/* ------------------------------------------------------------------ */
esp_err_t aktualino_store_have_creds(bool *out)
{
    if (out) *out = false;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;   /* namespace absent */
    if (err != ESP_OK) return err;

    /* "Have creds" == a stored client cert + key + gateway URL + uuid. */
    size_t n = 0;
    bool ok = (nvs_get_str(h, K_UUID,  NULL, &n) == ESP_OK) &&
              (nvs_get_str(h, K_GWURL, NULL, &n) == ESP_OK) &&
              (nvs_get_str(h, K_CERT,  NULL, &n) == ESP_OK) &&
              (nvs_get_str(h, K_PKEY,  NULL, &n) == ESP_OK);
    nvs_close(h);
    if (out) *out = ok;
    return ESP_OK;
}

esp_err_t aktualino_store_save_creds(const aktualino_creds_t *creds)
{
    if (!creds || !creds->uuid || !creds->gateway_url ||
        !creds->client_cert_pem || !creds->client_key_pem ||
        !creds->cacert_pem || !creds->ecu_serial) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    err  = nvs_set_str(h, K_UUID,   creds->uuid);
    err |= nvs_set_str(h, K_GWURL,  creds->gateway_url);
    err |= nvs_set_str(h, K_CERT,   creds->client_cert_pem);
    err |= nvs_set_str(h, K_PKEY,   creds->client_key_pem);
    err |= nvs_set_str(h, K_CACERT, creds->cacert_pem);
    err |= nvs_set_str(h, K_ECUSER, creds->ecu_serial);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "saved device identity: uuid=%s ecu_serial=%s",
                 creds->uuid, creds->ecu_serial);
    } else {
        ESP_LOGE(TAG, "save_creds failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t aktualino_store_load_creds(aktualino_creds_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err != ESP_OK) return err;

    char *uuid = NULL, *gw = NULL, *cert = NULL, *pkey = NULL,
         *ca = NULL, *ecu = NULL;
    err  = get_str_dup(h, K_UUID,   &uuid);
    if (err == ESP_OK) err = get_str_dup(h, K_GWURL,  &gw);
    if (err == ESP_OK) err = get_str_dup(h, K_CERT,   &cert);
    if (err == ESP_OK) err = get_str_dup(h, K_PKEY,   &pkey);
    if (err == ESP_OK) err = get_str_dup(h, K_CACERT, &ca);
    if (err == ESP_OK) err = get_str_dup(h, K_ECUSER, &ecu);
    nvs_close(h);

    if (err != ESP_OK) {
        free(uuid); free(gw); free(cert); free(pkey); free(ca); free(ecu);
        return err;
    }
    out->uuid = uuid; out->gateway_url = gw; out->client_cert_pem = cert;
    out->client_key_pem = pkey; out->cacert_pem = ca; out->ecu_serial = ecu;
    return ESP_OK;
}

void aktualino_store_free_creds(aktualino_creds_t *creds)
{
    if (!creds) return;
    free((void *)creds->uuid);
    free((void *)creds->gateway_url);
    free((void *)creds->client_cert_pem);
    free((void *)creds->client_key_pem);
    free((void *)creds->cacert_pem);
    free((void *)creds->ecu_serial);
    memset(creds, 0, sizeof(*creds));
}

/* ---- Wi-Fi station credentials (SPEC §6.1) ------------------------ */
esp_err_t aktualino_store_have_wifi(bool *out)
{
    if (out) *out = false;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    size_t n = 0;
    bool ok = (nvs_get_str(h, K_WIFISSID, NULL, &n) == ESP_OK);
    nvs_close(h);
    if (out) *out = ok;
    return ESP_OK;
}

esp_err_t aktualino_store_save_wifi(const char *ssid, const char *password)
{
    if (!ssid || !ssid[0]) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err  = nvs_set_str(h, K_WIFISSID, ssid);
    err |= nvs_set_str(h, K_WIFIPASS, password ? password : "");
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "saved Wi-Fi credentials for SSID \"%s\"", ssid);
    return err;
}

esp_err_t aktualino_store_load_wifi(char *ssid_buf, size_t ssid_cap,
                                    char *pass_buf, size_t pass_cap,
                                    bool *present)
{
    if (present) *present = false;
    if (ssid_buf && ssid_cap) ssid_buf[0] = '\0';
    if (pass_buf && pass_cap) pass_buf[0] = '\0';

    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;

    size_t n = ssid_cap;
    esp_err_t e1 = nvs_get_str(h, K_WIFISSID, ssid_buf, &n);
    if (e1 != ESP_OK) { nvs_close(h); return ESP_OK; }   /* none stored */
    if (pass_buf && pass_cap) {
        n = pass_cap;
        if (nvs_get_str(h, K_WIFIPASS, pass_buf, &n) != ESP_OK) pass_buf[0] = '\0';
    }
    nvs_close(h);
    if (present) *present = true;
    return ESP_OK;
}

/* ---- Path-B provisioning credential (runtime-entered) ------------- */
esp_err_t aktualino_store_have_prov_cred(bool *out)
{
    if (out) *out = false;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    size_t n = 0;
    bool ok = (nvs_get_str(h, K_PROVCRED, NULL, &n) == ESP_OK && n > 1);
    nvs_close(h);
    if (out) *out = ok;
    return ESP_OK;
}

esp_err_t aktualino_store_save_prov_cred(const char *cred)
{
    if (!cred) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, K_PROVCRED, cred);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t aktualino_store_load_prov_cred(char *buf, size_t cap, bool *present)
{
    if (present) *present = false;
    if (buf && cap) buf[0] = '\0';
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    size_t n = cap;
    esp_err_t e1 = nvs_get_str(h, K_PROVCRED, buf, &n);
    nvs_close(h);
    if (e1 != ESP_OK) { if (buf && cap) buf[0] = '\0'; return ESP_OK; }
    if (present) *present = (buf && buf[0] != '\0');
    return ESP_OK;
}

esp_err_t aktualino_store_clear_prov_cred(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    nvs_erase_key(h, K_PROVCRED);
    err = nvs_commit(h);
    nvs_close(h);
    return err;
}

/* ---- ECU keypair -------------------------------------------------- */
esp_err_t aktualino_store_have_ecu_key(bool *out)
{
    if (out) *out = false;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    size_t n = 0;
    bool ok = (nvs_get_blob(h, K_ECUPK, NULL, &n) == ESP_OK && n == 32);
    n = 0;
    ok = ok && (nvs_get_blob(h, K_ECUSK, NULL, &n) == ESP_OK && n == 64);
    nvs_close(h);
    if (out) *out = ok;
    return ESP_OK;
}

esp_err_t aktualino_store_save_ecu_key(const uint8_t pk[32], const uint8_t sk[64])
{
    if (!pk || !sk) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err  = nvs_set_blob(h, K_ECUPK, pk, 32);
    err |= nvs_set_blob(h, K_ECUSK, sk, 64);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t aktualino_store_load_ecu_key(uint8_t pk[32], uint8_t sk[64])
{
    if (!pk || !sk) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t np = 32, ns = 64;
    err  = nvs_get_blob(h, K_ECUPK, pk, &np);
    if (err == ESP_OK) err = nvs_get_blob(h, K_ECUSK, sk, &ns);
    nvs_close(h);
    if (err == ESP_OK && (np != 32 || ns != 64)) return ESP_ERR_INVALID_SIZE;
    return err;
}

/* ---- provisioned flag --------------------------------------------- */
esp_err_t aktualino_store_set_provisioned(bool value)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(h, K_PROV, value ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t aktualino_store_is_provisioned(bool *out)
{
    if (out) *out = false;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    uint8_t v = 0;
    err = nvs_get_u8(h, K_PROV, &v);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;   /* flag never set */
    if (err != ESP_OK) return err;
    if (out) *out = (v != 0);
    return ESP_OK;
}

/* ---- per-device identity nonce ------------------------------------ */
esp_err_t aktualino_store_get_or_init_id_nonce(uint32_t fresh, uint32_t *out)
{
    if (out) *out = fresh;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    uint32_t v = 0;
    err = nvs_get_u32(h, K_NONCE, &v);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        v = fresh;
        err = nvs_set_u32(h, K_NONCE, v);
        if (err == ESP_OK) err = nvs_commit(h);
    }
    nvs_close(h);
    if (err != ESP_OK) return err;
    if (out) *out = v;
    return ESP_OK;
}

/* ---- install state (Phase 3 full update loop) --------------------- */
esp_err_t aktualino_store_set_running_image(const char *filepath,
                                            const uint8_t sha256[32],
                                            uint32_t length)
{
    if (!filepath || !sha256) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err  = nvs_set_str(h, K_RUNFP, filepath);
    err |= nvs_set_blob(h, K_RUNSHA, sha256, 32);
    err |= nvs_set_u32(h, K_RUNLEN, length);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "running image recorded: %s (len=%lu)", filepath,
                 (unsigned long)length);
    return err;
}

esp_err_t aktualino_store_get_running_image(char *fp_buf, size_t fp_cap,
                                            uint8_t sha256[32], uint32_t *length,
                                            bool *present)
{
    if (present) *present = false;
    if (fp_buf && fp_cap) fp_buf[0] = '\0';
    if (length) *length = 0;
    if (sha256) memset(sha256, 0, 32);

    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;

    size_t shlen = 32;
    uint8_t sh[32];
    esp_err_t e1 = nvs_get_blob(h, K_RUNSHA, sh, &shlen);
    if (e1 != ESP_OK || shlen != 32) { nvs_close(h); return ESP_OK; } /* never set */

    if (sha256) memcpy(sha256, sh, 32);
    if (length) nvs_get_u32(h, K_RUNLEN, length);
    if (fp_buf && fp_cap) {
        size_t n = fp_cap;
        if (nvs_get_str(h, K_RUNFP, fp_buf, &n) != ESP_OK) fp_buf[0] = '\0';
    }
    nvs_close(h);
    if (present) *present = true;
    return ESP_OK;
}

esp_err_t aktualino_store_set_pending_update(const char *filepath,
                                             const uint8_t sha256[32],
                                             uint32_t length,
                                             const char *correlation_id)
{
    if (!filepath || !sha256) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err  = nvs_set_str(h, K_PNDFP, filepath);
    err |= nvs_set_blob(h, K_PNDSHA, sha256, 32);
    err |= nvs_set_u32(h, K_PNDLEN, length);
    err |= nvs_set_str(h, K_PNDCID, correlation_id ? correlation_id : "");
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "pending update staged: %s (cid=%s)", filepath,
                 correlation_id ? correlation_id : "");
    return err;
}

esp_err_t aktualino_store_get_pending_update(char *fp_buf, size_t fp_cap,
                                             uint8_t sha256[32], uint32_t *length,
                                             char *cid_buf, size_t cid_cap,
                                             bool *present)
{
    if (present) *present = false;
    if (fp_buf && fp_cap) fp_buf[0] = '\0';
    if (cid_buf && cid_cap) cid_buf[0] = '\0';
    if (length) *length = 0;
    if (sha256) memset(sha256, 0, 32);

    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;

    size_t shlen = 32;
    uint8_t sh[32];
    esp_err_t e1 = nvs_get_blob(h, K_PNDSHA, sh, &shlen);
    if (e1 != ESP_OK || shlen != 32) { nvs_close(h); return ESP_OK; } /* none staged */

    if (sha256) memcpy(sha256, sh, 32);
    if (length) nvs_get_u32(h, K_PNDLEN, length);
    if (fp_buf && fp_cap) {
        size_t n = fp_cap;
        if (nvs_get_str(h, K_PNDFP, fp_buf, &n) != ESP_OK) fp_buf[0] = '\0';
    }
    if (cid_buf && cid_cap) {
        size_t n = cid_cap;
        if (nvs_get_str(h, K_PNDCID, cid_buf, &n) != ESP_OK) cid_buf[0] = '\0';
    }
    nvs_close(h);
    if (present) *present = true;
    return ESP_OK;
}

esp_err_t aktualino_store_clear_pending_update(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    nvs_erase_key(h, K_PNDFP);
    nvs_erase_key(h, K_PNDSHA);
    nvs_erase_key(h, K_PNDLEN);
    nvs_erase_key(h, K_PNDCID);
    err = nvs_commit(h);
    nvs_close(h);
    return err;
}

/* ---- TUF metadata blobs ------------------------------------------- */
/* Sanitize a name into a <=15-char NVS key ('/' -> '_'). */
static void meta_key(const char *name, char out[16])
{
    size_t j = 0;
    for (size_t i = 0; name[i] && j < 15; i++) {
        char c = name[i];
        out[j++] = (c == '/') ? '_' : c;
    }
    out[j] = '\0';
}

esp_err_t aktualino_store_put_metadata(const char *name,
                                       const void *buf, size_t len)
{
    if (!name || !buf) return ESP_ERR_INVALID_ARG;
    char key[16]; meta_key(name, key);
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_TUF, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, key, buf, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t aktualino_store_get_metadata(const char *name,
                                       void *buf, size_t cap, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!name) return ESP_ERR_INVALID_ARG;
    char key[16]; meta_key(name, key);
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_TUF, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t len = cap;
    err = nvs_get_blob(h, key, buf, &len);
    nvs_close(h);
    if (err == ESP_OK && out_len) *out_len = len;
    return err;
}

/* ---- per-role metadata versions (rollback protection, SPEC §7.2) ---- */
/* NVS key "ver_<role>" (<=15 chars: ver_timestamp = 13). */
static void ver_key(const char *role, char out[16])
{
    snprintf(out, 16, "ver_%s", role ? role : "");
}

esp_err_t aktualino_store_get_meta_version(const char *role, int32_t *out)
{
    if (out) *out = 0;
    if (!role) return ESP_ERR_INVALID_ARG;
    char key[16]; ver_key(role, key);
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_TUF, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;    /* namespace absent */
    if (err != ESP_OK) return err;
    int32_t v = 0;
    err = nvs_get_i32(h, key, &v);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;    /* never stored */
    if (err != ESP_OK) return err;
    if (out) *out = v;
    return ESP_OK;
}

esp_err_t aktualino_store_set_meta_version(const char *role, int32_t version)
{
    if (!role) return ESP_ERR_INVALID_ARG;
    char key[16]; ver_key(role, key);
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_TUF, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_i32(h, key, version);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t aktualino_store_reset_tuf(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_TUF, NVS_READWRITE, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    err = nvs_erase_all(h);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "TUF metadata reset (SPEC §8 stale-root reset)");
    return err;
}

esp_err_t aktualino_store_reset(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_ID, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err;
    }
    ESP_LOGW(TAG, "device identity + ECU key cleared (factory reset)");
    return aktualino_store_reset_tuf();
}
