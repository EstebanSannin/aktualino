/*
 * aktualino_prov — device ECU self-registration + V3 device manifest against the
 * OTA-Connect device gateway (Torizon Cloud), plus the on-device Torizon Cloud
 * self-provision path (SPEC §6, Appendix A). T1.5.
 *
 * Per-device mTLS credentials (client cert/key, gateway URL, pinned server CA,
 * device UUID) come from Torizon Cloud provisioning — either fetched on-device by
 * aktualino_prov_torizon_fetch_creds() (device.zip) or seeded into NVS by a host
 * injector (tools/aktualino-provision.py). Once those credentials are present in
 * aktualino_store, aktualino_prov_run() finishes enrolment:
 *   1. Generate the on-device Ed25519 ECU keypair; derive the ECU serial and
 *      hardware id.
 *   2. POST {gateway}/director/ecus (mTLS) with the RegisterDevice body carrying
 *      the ECU public key -> 201/200.
 *   3. PUT {gateway}/director/manifest (mTLS) with a V3 device manifest signed by
 *      the ECU key -> 200.
 *
 * THE CRUX (SPEC §8 / Appendix A): the director derives each signature's keyid
 * from clientKey as sha256(X.509 SubjectPublicKeyInfo DER of the raw Ed25519
 * public key), hex. aktualino_crypto computes the manifest keyids identically
 * (akt_keyid_ed25519), and the TUF key JSON encodes the public as hex of the raw
 * 32 bytes (bytesToHex of the raw key). So the registered key's keyid matches the
 * manifest signature keyid and the director accepts the manifest.
 */
#include "aktualino_prov.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_app_desc.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"

#include "cJSON.h"
#include "miniz.h"          /* ROM tinfl: inflate the device.zip members (A2) */

#include "aktualino_store.h"
#include "aktualino_net.h"
#include "akt_crypto.h"
#include "akt_uptane.h"

static const char *TAG = "akt_prov";

/* Trust-anchor NVS blob names — MUST match aktualino_core's ROOT_BLOB_NAME /
 * IMG_ROOT_BLOB_NAME so a Torizon-seeded root is found by the poll loop. */
#define ROOT_BLOB_DIRECTOR "director/root"
#define ROOT_BLOB_IMAGE    "image/root"

/* ---- identity derivation from the eFuse MAC ----------------------- */

/*
 * ECU serial: the exact ValidEcuIdentifier predicate lives in a compiled libats
 * jar (SPEC Appendix A "Constraints"). The director's own test generator
 * (Generators.GenEcuIdentifier) restricts serials to alphabetic chars, length
 * 10-64, so we use that proven-valid form: "aktualinoesp" + each MAC nibble
 * mapped to a lowercase letter a-p. 12 + 12 = 24 alphabetic chars.
 */
/*
 * ECU serial = "aktualinoesp" + 12 MAC nibbles + 8 nonce nibbles, each nibble
 * mapped to a lowercase letter a-p → 12+12+8 = 32 alphabetic chars (valid: the
 * ValidEcuIdentifier predicate accepts alphabetic, length 10-64). The persistent
 * `nonce` keeps this globally unique across boards and across re-enrolments,
 * side-stepping the SPEC §8 "ECU already registered elsewhere" collision.
 */
static void derive_ecu_serial(char out[40], uint32_t nonce)
{
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    const char *pfx = "aktualinoesp";
    size_t p = strlen(pfx);
    memcpy(out, pfx, p);
    for (int i = 0; i < 6; i++) {
        out[p++] = 'a' + (mac[i] >> 4);
        out[p++] = 'a' + (mac[i] & 0x0f);
    }
    for (int i = 7; i >= 0; i--) {
        out[p++] = 'a' + ((nonce >> (i * 4)) & 0x0f);
    }
    out[p] = '\0';
}

#if CONFIG_AKTUALINO_SCRIPT_SECONDARY
/*
 * Secondary (Berry script) ecu_serial = "lua" + the primary serial. Deterministic
 * (so registration and every manifest agree without extra NVS), unique per
 * device, and alphabetic — a valid ecu identifier (spec §3). With the 32-char
 * primary this is 35 chars, well within the 10–64 predicate.
 */
static void derive_secondary_serial(const char *primary, char out[70])
{
    snprintf(out, 70, "lua%s", primary);
}
#endif

static void derive_device_name(char out[48], uint32_t nonce)
{
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(out, 48, "aktualino-esp32-%02x%02x%02x-%08lx",
             mac[3], mac[4], mac[5], (unsigned long)nonce);
}

/* ---- JSON helpers ------------------------------------------------- */
static char *dup_json_str(const cJSON *o, const char *k)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!cJSON_IsString(v) || !v->valuestring) return NULL;
    return strdup(v->valuestring);
}

/* ---- POST /director/ecus (mTLS) ---------------------------------- */
static esp_err_t register_ecu(const aktualino_prov_inputs_t *in,
                              const aktualino_creds_t *creds,
                              const uint8_t pk[32])
{
    char pk_hex[65];
    if (akt_hex_encode(pk, 32, pk_hex, sizeof(pk_hex)) != 0) return ESP_FAIL;

    /* Body: { primary_ecu_serial, ecus:[{ ecu_serial, hardware_identifier,
     *         clientKey:{keytype:"ED25519", keyval:{public:<hex>}} }] } */
    cJSON *root = cJSON_CreateObject();
    cJSON *ecus = cJSON_CreateArray();
    cJSON *ecu = cJSON_CreateObject();
    cJSON *key = cJSON_CreateObject();
    cJSON *keyval = cJSON_CreateObject();
    if (!root || !ecus || !ecu || !key || !keyval) {
        cJSON_Delete(root); cJSON_Delete(ecus); cJSON_Delete(ecu);
        cJSON_Delete(key); cJSON_Delete(keyval);
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(keyval, "public", pk_hex);
    cJSON_AddStringToObject(key, "keytype", "ED25519");
    cJSON_AddItemToObject(key, "keyval", keyval);
    cJSON_AddStringToObject(ecu, "ecu_serial", creds->ecu_serial);
    cJSON_AddStringToObject(ecu, "hardware_identifier",
                            in->hardware_id ? in->hardware_id : "aktualino-esp32");
    cJSON_AddItemToObject(ecu, "clientKey", key);
    cJSON_AddItemToArray(ecus, ecu);

#if CONFIG_AKTUALINO_SCRIPT_SECONDARY
    /* Register the Berry script secondary as a SECOND ECU, reusing the primary's
     * Ed25519 clientKey (spec §3): the director keys verification per ecu_serial,
     * and both ECUs are the same chip. `VALIDATE`: this is the point that proves
     * the director accepts two ECUs sharing a clientKey. */
    {
        char lua_serial[70];
        derive_secondary_serial(creds->ecu_serial, lua_serial);
        cJSON *ecu2 = cJSON_CreateObject();
        cJSON *key2 = cJSON_CreateObject();
        cJSON *keyval2 = cJSON_CreateObject();
        if (ecu2 && key2 && keyval2) {
            cJSON_AddStringToObject(keyval2, "public", pk_hex);   /* same key */
            cJSON_AddStringToObject(key2, "keytype", "ED25519");
            cJSON_AddItemToObject(key2, "keyval", keyval2);
            cJSON_AddStringToObject(ecu2, "ecu_serial", lua_serial);
            cJSON_AddStringToObject(ecu2, "hardware_identifier", "aktualino-lua");
            cJSON_AddItemToObject(ecu2, "clientKey", key2);
            cJSON_AddItemToArray(ecus, ecu2);
            ESP_LOGI(TAG, "ecu-register: + secondary %s (hwid aktualino-lua, key reuse)",
                     lua_serial);
        } else {
            cJSON_Delete(ecu2); cJSON_Delete(key2); cJSON_Delete(keyval2);
        }
    }
#endif

    cJSON_AddStringToObject(root, "primary_ecu_serial", creds->ecu_serial);
    cJSON_AddItemToObject(root, "ecus", ecus);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) return ESP_ERR_NO_MEM;

    char url[256];
    snprintf(url, sizeof(url), "%s/director/ecus", creds->gateway_url);
    const char *ca = in->server_ca_pem ? in->server_ca_pem : creds->cacert_pem;

    ESP_LOGI(TAG, "ecu-register: POST %s (keyid via sha256(SPKI))", url);
    aktualino_net_req_cfg_t cfg = {
        .url = url, .method = "POST",
        .cacert_pem = ca,
        .client_cert_pem = creds->client_cert_pem,
        .client_key_pem = creds->client_key_pem,
        .content_type = "application/json",
        .body = body, .body_len = strlen(body),
        .timeout_ms = 20000,
    };
    char *resp = NULL; size_t rlen = 0; int status = 0;
    esp_err_t err = aktualino_net_request(&cfg, &resp, &rlen, &status);
    free(body);
    if (err != ESP_OK) { free(resp); return err; }
    if (status == 200 || status == 201) {
        ESP_LOGI(TAG, "ecu-register OK: HTTP %d", status);
        free(resp);
        return ESP_OK;
    }
    ESP_LOGE(TAG, "ecu-register HTTP %d; body: %.256s", status, resp ? resp : "");
    free(resp);
    return ESP_FAIL;
}

/* ---- step 4 / heartbeat: PUT /director/manifest (mTLS) ------------- */

/*
 * PUT a V3 device manifest. When `correlation_id` is non-NULL the manifest
 * carries an installation_report (success/failure) so the director marks the
 * matching assignment completed. `inst` is the installed_image to report.
 */
static esp_err_t post_manifest(const aktualino_creds_t *creds,
                               const char *server_ca_pem,
                               const uint8_t pk[32], const uint8_t sk[64],
                               const akt_target_t *inst,
                               const char *correlation_id, bool success,
                               const akt_secondary_t *sec_override)
{
    size_t mlen = 0;
    char *man;
#if CONFIG_AKTUALINO_SCRIPT_SECONDARY
    /* Report the secondary ECU alongside the primary. `sec_override` (from
     * aktualino_script) carries the real installed bundle + its correlation id so
     * the secondary update completes; without it we report the empty-image
     * placeholder (filepath "unknown", length 0, sha256 of "") — a heartbeat. */
    char lua_serial[70];
    derive_secondary_serial(creds->ecu_serial, lua_serial);
    static const uint8_t SHA256_EMPTY[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14, 0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c, 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55 };
    akt_secondary_t sec;
    if (sec_override) {
        sec = *sec_override;              /* real installed bundle + correlation */
        sec.ecu_serial = lua_serial;      /* always our derived serial */
    } else {
        memset(&sec, 0, sizeof(sec));
        sec.ecu_serial = lua_serial;
        sec.attacks_detected = "";
        strcpy(sec.installed.filepath, "unknown");
        sec.installed.length = 0;
        memcpy(sec.installed.sha256, SHA256_EMPTY, 32);
    }
    man = akt_build_manifest_ex(creds->ecu_serial, inst, "",
                                correlation_id, success, &sec, pk, sk, &mlen);
#else
    (void)sec_override;
    man = akt_build_manifest_report(creds->ecu_serial, inst, "",
                                    correlation_id, success, pk, sk, &mlen);
#endif
    if (!man) { ESP_LOGE(TAG, "manifest build failed"); return ESP_FAIL; }

    char url[256];
    snprintf(url, sizeof(url), "%s/director/manifest", creds->gateway_url);
    const char *ca = server_ca_pem ? server_ca_pem : creds->cacert_pem;

    ESP_LOGI(TAG, "manifest: PUT %s (%zu bytes%s)", url, mlen,
             correlation_id ? ", with installation_report" : "");
    aktualino_net_req_cfg_t cfg = {
        .url = url, .method = "PUT",
        .cacert_pem = ca,
        .client_cert_pem = creds->client_cert_pem,
        .client_key_pem = creds->client_key_pem,
        .content_type = "application/json",
        .body = man, .body_len = mlen,
        .timeout_ms = 20000,
    };
    char *resp = NULL; size_t rlen = 0; int status = 0;
    esp_err_t err = aktualino_net_request(&cfg, &resp, &rlen, &status);
    free(man);
    if (err != ESP_OK) { free(resp); return err; }
    if (status == 200 || status == 204) {
        ESP_LOGI(TAG, "manifest ACCEPTED: HTTP %d", status);
        free(resp);
        return ESP_OK;
    }
    ESP_LOGE(TAG, "manifest REJECTED: HTTP %d; body: %.512s",
             status, resp ? resp : "");
    free(resp);
    return ESP_FAIL;
}

/*
 * Fill `inst` with the image to report as currently installed. If a Director
 * target was installed and confirmed (Phase 3), report exactly that target
 * (filepath + sha256 + length) so the director's "current image" matches the
 * assignment. Otherwise (fresh Phase-1 device) report the running firmware by
 * its ELF SHA-256 and version-derived filepath — the acceptance gate for a
 * first/heartbeat manifest is the SIGNATURE keyid, not the image bytes.
 */
static void fill_current_installed(akt_target_t *inst, const char *hardware_id)
{
    memset(inst, 0, sizeof(*inst));

    char fp[254]; uint8_t sha[32]; uint32_t len = 0; bool present = false;
    if (aktualino_store_get_running_image(fp, sizeof(fp), sha, &len, &present) == ESP_OK
        && present) {
        snprintf(inst->filepath, sizeof(inst->filepath), "%s", fp);
        memcpy(inst->sha256, sha, 32);
        inst->length = len;
        return;
    }

    const esp_app_desc_t *app = esp_app_get_description();
    const esp_partition_t *run = esp_ota_get_running_partition();
    snprintf(inst->filepath, sizeof(inst->filepath), "%s-%s",
             hardware_id ? hardware_id : "aktualino-esp32",
             app ? app->version : "0");
    if (app) memcpy(inst->sha256, app->app_elf_sha256, 32);
    else     akt_sha256("aktualino", 9, inst->sha256);
    inst->length = run ? run->size : 1;
}

/* First/heartbeat manifest: report the current installed image, no report. */
static esp_err_t send_manifest(const aktualino_prov_inputs_t *in,
                               const aktualino_creds_t *creds,
                               const uint8_t pk[32], const uint8_t sk[64])
{
    akt_target_t inst;
    fill_current_installed(&inst, in->hardware_id);
    return post_manifest(creds, in->server_ca_pem, pk, sk, &inst, NULL, true, NULL);
}

/* ================================================================== *
 * Torizon Cloud on-device self-provision (Path A2 / Path B), SPEC §6.
 * The exact calls tools/aktualino-provision.py validated, moved on-device.
 * ================================================================== */

#define TORIZON_DEVICES_URL_DEFAULT "https://app.torizon.io/api/accounts/devices"

/* rfc3986 form-urlencode into out (returns bytes written, excl. NUL). */
static size_t form_urlencode(const char *s, char *out, size_t cap)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (size_t i = 0; s && s[i] && j + 4 < cap; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            out[j++] = '%'; out[j++] = hex[c >> 4]; out[j++] = hex[c & 0x0f];
        }
    }
    out[j] = '\0';
    return j;
}

/*
 * Extract one member of a ZIP archive (`zip`, `ziplen`) by filename via the
 * central directory, inflating a DEFLATE member with ROM miniz. Returns a
 * malloc'd, NUL-terminated buffer (caller frees) and its length via *out_len,
 * or NULL if the member is absent/corrupt. Robust to data-descriptor members
 * because the central directory always carries the true sizes + local offset.
 */
static uint32_t rd_u16(const uint8_t *p) { return p[0] | (p[1] << 8); }
static uint32_t rd_u32(const uint8_t *p) { return p[0] | (p[1]<<8) | (p[2]<<16) | ((uint32_t)p[3]<<24); }

static char *zip_extract(const uint8_t *zip, size_t ziplen,
                         const char *want, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (ziplen < 22) return NULL;

    /* Find the End Of Central Directory record (sig 0x06054b50), scanning back. */
    size_t eocd = 0; bool found = false;
    for (size_t i = ziplen - 22 + 1; i-- > 0; ) {
        if (rd_u32(zip + i) == 0x06054b50) { eocd = i; found = true; break; }
        if (ziplen - i > 22 + 65535) break;   /* comment can't exceed 64 KB */
    }
    if (!found) return NULL;

    uint32_t nent = rd_u16(zip + eocd + 10);
    uint32_t cd_off = rd_u32(zip + eocd + 16);
    size_t p = cd_off;
    for (uint32_t e = 0; e < nent && p + 46 <= ziplen; e++) {
        if (rd_u32(zip + p) != 0x02014b50) break;
        uint32_t method  = rd_u16(zip + p + 10);
        uint32_t comp    = rd_u32(zip + p + 20);
        uint32_t uncomp  = rd_u32(zip + p + 24);
        uint32_t nlen    = rd_u16(zip + p + 28);
        uint32_t elen    = rd_u16(zip + p + 30);
        uint32_t clen    = rd_u16(zip + p + 32);
        uint32_t lho     = rd_u32(zip + p + 42);
        const char *name = (const char *)(zip + p + 46);

        bool match = (strlen(want) == nlen) && (memcmp(name, want, nlen) == 0);
        if (match) {
            /* Data starts after the LOCAL header (its own name+extra lengths). */
            if (lho + 30 > ziplen) return NULL;
            uint32_t l_nlen = rd_u16(zip + lho + 26);
            uint32_t l_elen = rd_u16(zip + lho + 28);
            size_t data = lho + 30 + l_nlen + l_elen;
            if (data + comp > ziplen) return NULL;

            if (method == 0) {                          /* STORED */
                char *out = malloc(uncomp + 1);
                if (!out) return NULL;
                memcpy(out, zip + data, uncomp);
                out[uncomp] = '\0';
                if (out_len) *out_len = uncomp;
                return out;
            }
            if (method == 8) {                          /* DEFLATE (raw) */
                /* The ROM exports only the low-level tinfl_decompress (not the
                 * _mem_to_heap helper), so drive it directly: full input, a
                 * non-wrapping output buffer sized to the member's uncompressed
                 * length from the central directory. Members here are < 1 KB. */
                char *out = malloc(uncomp + 1);
                tinfl_decompressor *d = malloc(sizeof(*d));
                if (!out || !d) { free(out); free(d); return NULL; }
                tinfl_init(d);
                size_t in_sz = comp, out_sz = uncomp;
                tinfl_status st = tinfl_decompress(
                    d, (const mz_uint8 *)(zip + data), &in_sz,
                    (mz_uint8 *)out, (mz_uint8 *)out, &out_sz,
                    TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
                free(d);
                if (st != TINFL_STATUS_DONE) { free(out); return NULL; }
                out[out_sz] = '\0';
                if (out_len) *out_len = out_sz;
                return out;
            }
            return NULL;                                 /* unsupported method */
        }
        p += 46 + nlen + elen + clen;
    }
    return NULL;
}

/* Mint an OAuth2 access token (client_credentials) -> *token_out (caller frees). */
static esp_err_t mint_token(const char *endpoint, const char *client_id,
                            const char *client_secret, char **token_out)
{
    *token_out = NULL;
    char id_enc[128], sec_enc[256];
    form_urlencode(client_id, id_enc, sizeof(id_enc));
    form_urlencode(client_secret, sec_enc, sizeof(sec_enc));

    char *body = malloc(600);
    if (!body) return ESP_ERR_NO_MEM;
    int blen = snprintf(body, 600,
        "grant_type=client_credentials&client_id=%s&client_secret=%s",
        id_enc, sec_enc);

    aktualino_net_req_cfg_t cfg = {
        .url = endpoint, .method = "POST",
        .content_type = "application/x-www-form-urlencoded",
        .body = body, .body_len = (size_t)blen, .timeout_ms = 30000,
    };
    char *resp = NULL; size_t rlen = 0; int status = 0;
    esp_err_t err = aktualino_net_request(&cfg, &resp, &rlen, &status);
    free(body);
    if (err != ESP_OK) { free(resp); return err; }
    if (status != 200) {
        ESP_LOGE(TAG, "token mint HTTP %d", status);
        free(resp); return ESP_FAIL;
    }
    cJSON *r = cJSON_Parse(resp);
    free(resp);
    if (!r) return ESP_FAIL;
    char *tok = dup_json_str(r, "access_token");
    cJSON_Delete(r);
    if (!tok) return ESP_FAIL;
    *token_out = tok;
    ESP_LOGI(TAG, "minted OAuth2 access token (%d chars)", (int)strlen(tok));
    return ESP_OK;
}

/* Seed one RSA trust anchor (root blob + version) into NVS from a root JSON. */
static void seed_root(const char *blob, const char *ver_tag,
                      const char *json, size_t len)
{
    if (!json || !len) return;
    aktualino_store_put_metadata(blob, json, len);
    cJSON *r = cJSON_Parse(json);
    if (r) {
        const cJSON *signed_o = cJSON_GetObjectItemCaseSensitive(r, "signed");
        const cJSON *v = signed_o ? cJSON_GetObjectItemCaseSensitive(signed_o, "version") : NULL;
        if (cJSON_IsNumber(v)) aktualino_store_set_meta_version(ver_tag, (int32_t)v->valuedouble);
        cJSON_Delete(r);
    }
    ESP_LOGI(TAG, "seeded trust anchor %s (%zu bytes)", blob, len);
}

esp_err_t aktualino_prov_torizon_fetch_creds(
    const aktualino_prov_torizon_inputs_t *in)
{
    if (!in) return ESP_ERR_INVALID_ARG;
    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    /* Stable identity nonce so a re-enrolled board gets a unique device id. */
    uint32_t nonce = 0;
    aktualino_store_get_or_init_id_nonce(esp_random(), &nonce);

    char id_buf[48];
    const char *dev_id = in->device_id;
    if (!dev_id || !dev_id[0]) { derive_device_name(id_buf, nonce); dev_id = id_buf; }
    const char *dev_name = (in->device_name && in->device_name[0]) ? in->device_name : dev_id;

    /* 1. token: mint from the baked client, or use a pasted bearer (Path B). */
    char *minted = NULL;
    const char *bearer = in->bearer_token;
    if (!bearer || !bearer[0]) {
        if (!in->token_endpoint || !in->client_id || !in->client_secret) {
            ESP_LOGE(TAG, "torizon: no bearer and no client_credentials to mint");
            return ESP_ERR_INVALID_ARG;
        }
        err = mint_token(in->token_endpoint, in->client_id, in->client_secret, &minted);
        if (err != ESP_OK) return err;
        bearer = minted;
    }

    /* 2. register the device -> device.zip (binary body). Torizon access tokens
     * are JWTs and can exceed 1 KB, so size the header buffer generously. */
    size_t auth_cap = strlen(bearer) + 16;
    char *auth = malloc(auth_cap);
    if (!auth) { free(minted); return ESP_ERR_NO_MEM; }
    snprintf(auth, auth_cap, "Bearer %s", bearer);
    cJSON *rq = cJSON_CreateObject();
    cJSON_AddStringToObject(rq, "device_id", dev_id);
    cJSON_AddStringToObject(rq, "device_name", dev_name);
    char *rqs = cJSON_PrintUnformatted(rq);
    cJSON_Delete(rq);

    const char *url = (in->devices_url && in->devices_url[0]) ? in->devices_url
                                                             : TORIZON_DEVICES_URL_DEFAULT;
    ESP_LOGI(TAG, "torizon: POST %s (device_id=%s)", url, dev_id);
    aktualino_net_req_cfg_t cfg = {
        .url = url, .method = "POST",
        .content_type = "application/json",
        .authorization = auth,
        .body = rqs, .body_len = rqs ? strlen(rqs) : 0,
        .timeout_ms = 60000,
    };
    char *zip = NULL; size_t ziplen = 0; int status = 0;
    err = aktualino_net_request(&cfg, &zip, &ziplen, &status);
    free(rqs);
    free(minted);
    free(auth);
    if (err != ESP_OK) { free(zip); return err; }
    if (status != 200 && status != 201) {
        ESP_LOGE(TAG, "torizon device register HTTP %d", status);
        free(zip); return ESP_FAIL;
    }
    ESP_LOGI(TAG, "torizon: device.zip received (%zu bytes)", ziplen);

    /* 3. inflate + extract the device identity, persist it. */
    size_t clen = 0, klen = 0, calen = 0, glen = 0, ilen = 0;
    char *cert = zip_extract((const uint8_t *)zip, ziplen, "client.pem", &clen);
    char *pkey = zip_extract((const uint8_t *)zip, ziplen, "pkey.pem", &klen);
    char *ca   = zip_extract((const uint8_t *)zip, ziplen, "root.crt", &calen);
    char *gw   = zip_extract((const uint8_t *)zip, ziplen, "gateway.url", &glen);
    char *info = zip_extract((const uint8_t *)zip, ziplen, "info.json", &ilen);
    free(zip);

    esp_err_t rc = ESP_FAIL;
    char *uuid = NULL;
    if (cert && pkey && ca && gw && info) {
        /* gateway.url may carry a trailing newline; trim it. */
        for (size_t i = strlen(gw); i > 0 && (gw[i-1]=='\n' || gw[i-1]=='\r' || gw[i-1]==' '); i--)
            gw[i-1] = '\0';
        cJSON *ij = cJSON_Parse(info);
        if (ij) { uuid = dup_json_str(ij, "deviceUuid"); cJSON_Delete(ij); }
        if (uuid) {
            char serial[40]; derive_ecu_serial(serial, nonce);
            aktualino_creds_t creds = {
                .uuid = uuid, .gateway_url = gw, .client_cert_pem = cert,
                .client_key_pem = pkey, .cacert_pem = ca, .ecu_serial = serial,
            };
            ESP_LOGI(TAG, "torizon: uuid=%s gateway=%s", uuid, gw);
            rc = aktualino_store_save_creds(&creds);
        } else {
            ESP_LOGE(TAG, "torizon: info.json has no deviceUuid");
        }
    } else {
        ESP_LOGE(TAG, "torizon: device.zip missing a member (cert=%p key=%p ca=%p gw=%p info=%p)",
                 cert, pkey, ca, gw, info);
    }

    /* 4. seed the Torizon RSA trust anchors so the poll loop verifies Torizon. */
    if (rc == ESP_OK) {
        seed_root(ROOT_BLOB_DIRECTOR, "root",     in->director_root_json, in->director_root_len);
        seed_root(ROOT_BLOB_IMAGE,    "img_root", in->image_root_json,    in->image_root_len);
    }

    free(cert); free(pkey); free(ca); free(gw); free(info); free(uuid);
    return rc;
}

/* ---- orchestration ------------------------------------------------ */
esp_err_t aktualino_prov_run(const aktualino_prov_inputs_t *in)
{
    if (!in) return ESP_ERR_INVALID_ARG;

    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    bool provisioned = false;
    aktualino_store_is_provisioned(&provisioned);
    if (provisioned) {
        ESP_LOGI(TAG, "already provisioned — skipping enrolment");
        return ESP_OK;
    }

    /* Stable per-device identity nonce (SPEC §8): fold into the ECU serial so a
     * re-enrolled board never collides with a stale server-side record. */
    uint32_t nonce = 0;
    aktualino_store_get_or_init_id_nonce(esp_random(), &nonce);
    ESP_LOGI(TAG, "device identity nonce = %08lx", (unsigned long)nonce);

    /* Step 1: credentials. These MUST already be in the store — obtained on-device
     * via aktualino_prov_torizon_fetch_creds() (device.zip) or seeded by a host
     * injector. This component does not mint credentials itself. */
    bool have = false;
    aktualino_store_have_creds(&have);
    if (!have) {
        ESP_LOGE(TAG, "no device credentials in store — fetch them from Torizon "
                      "Cloud provisioning (device.zip) before enrolling");
        return ESP_ERR_INVALID_STATE;
    }
    ESP_LOGI(TAG, "device credentials present — enrolling ECU + first manifest");

    aktualino_creds_t creds;
    err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "load_creds failed: %s", esp_err_to_name(err));
        return err;
    }

    /* Step 2: ECU keypair (persist so the keyid is stable across reboots). */
    uint8_t pk[32], sk[64];
    bool have_key = false;
    aktualino_store_have_ecu_key(&have_key);
    if (!have_key) {
        if (akt_keygen_ed25519(pk, sk) != 0) { err = ESP_FAIL; goto out; }
        err = aktualino_store_save_ecu_key(pk, sk);
        if (err != ESP_OK) goto out;
        ESP_LOGI(TAG, "generated on-device Ed25519 ECU key");
    } else {
        err = aktualino_store_load_ecu_key(pk, sk);
        if (err != ESP_OK) goto out;
    }
    {
        char kid[65];
        if (akt_keyid_ed25519(pk, kid) == 0)
            ESP_LOGI(TAG, "ECU keyid = %s", kid);
    }

    /* Step 3: register the ECU with the director. */
    err = register_ecu(in, &creds, pk);
    if (err != ESP_OK) goto out;

    /* Step 4: first signed manifest. */
    err = send_manifest(in, &creds, pk, sk);
    if (err != ESP_OK) goto out;

    err = aktualino_store_set_provisioned(true);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "provisioning COMPLETE — device is registered and current");

out:
    aktualino_store_free_creds(&creds);
    return err;
}

esp_err_t aktualino_prov_is_provisioned(bool *out)
{
    if (out) *out = false;
    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;
    return aktualino_store_is_provisioned(out);
}

esp_err_t aktualino_prov_report_current(const char *hardware_id)
{
    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    aktualino_creds_t creds;
    err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "report_current: load_creds failed: %s",
                 esp_err_to_name(err));
        return err;
    }
    uint8_t pk[32], sk[64];
    err = aktualino_store_load_ecu_key(pk, sk);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "report_current: load_ecu_key failed: %s",
                 esp_err_to_name(err));
        aktualino_store_free_creds(&creds);
        return err;
    }

    /* server_ca_pem NULL => post_manifest pins creds->cacert_pem. */
    aktualino_prov_inputs_t in = {
        .hardware_id   = hardware_id ? hardware_id : "aktualino-esp32",
        .server_ca_pem = NULL,
    };
    err = send_manifest(&in, &creds, pk, sk);
    aktualino_store_free_creds(&creds);
    return err;
}

esp_err_t aktualino_prov_report_installed(const char *filepath,
                                          const uint8_t sha256[32],
                                          uint32_t length,
                                          const char *correlation_id,
                                          bool success)
{
    if (!filepath || !sha256) return ESP_ERR_INVALID_ARG;
    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    aktualino_creds_t creds;
    err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "report_installed: load_creds failed: %s",
                 esp_err_to_name(err));
        return err;
    }
    uint8_t pk[32], sk[64];
    err = aktualino_store_load_ecu_key(pk, sk);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "report_installed: load_ecu_key failed: %s",
                 esp_err_to_name(err));
        aktualino_store_free_creds(&creds);
        return err;
    }

    akt_target_t inst;
    memset(&inst, 0, sizeof(inst));
    snprintf(inst.filepath, sizeof(inst.filepath), "%s", filepath);
    memcpy(inst.sha256, sha256, 32);
    inst.length = length;

    ESP_LOGW(TAG, "reporting installed target %s (%s) cid=%s", filepath,
             success ? "SUCCESS" : "FAILURE",
             correlation_id ? correlation_id : "(none)");
    err = post_manifest(&creds, NULL, pk, sk, &inst,
                        (correlation_id && correlation_id[0]) ? correlation_id : NULL,
                        success, NULL);
    aktualino_store_free_creds(&creds);
    return err;
}

#if CONFIG_AKTUALINO_SCRIPT_SECONDARY
esp_err_t aktualino_prov_report_secondary(const char *filepath,
                                          const uint8_t sha256[32], size_t length,
                                          const char *correlation_id, bool success)
{
    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    aktualino_creds_t creds;
    err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) return err;
    uint8_t pk[32], sk[64];
    err = aktualino_store_load_ecu_key(pk, sk);
    if (err != ESP_OK) { aktualino_store_free_creds(&creds); return err; }

    /* Primary reported as its current running image (heartbeat); the secondary
     * carries the installed bundle + the correlation id that completes its
     * update (installation_report scoped to the secondary — akt_build_manifest_ex). */
    akt_target_t primary;
    fill_current_installed(&primary, NULL);

    akt_secondary_t sec;
    memset(&sec, 0, sizeof(sec));
    sec.attacks_detected = "";
    snprintf(sec.installed.filepath, sizeof(sec.installed.filepath), "%s",
             filepath ? filepath : "unknown");
    memcpy(sec.installed.sha256, sha256, 32);
    sec.installed.length = length;
    sec.correlation_id = (correlation_id && correlation_id[0]) ? correlation_id : NULL;
    sec.success = success;

    ESP_LOGW(TAG, "reporting SECONDARY bundle %s (%s) cid=%s", filepath,
             success ? "SUCCESS" : "FAILURE", correlation_id ? correlation_id : "(none)");
    /* Primary correlation NULL (this manifest completes the SECONDARY's update). */
    err = post_manifest(&creds, NULL, pk, sk, &primary, NULL, true, &sec);
    aktualino_store_free_creds(&creds);
    return err;
}
#endif

esp_err_t aktualino_prov_report_failed(const char *hardware_id,
                                       const char *correlation_id)
{
    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    aktualino_creds_t creds;
    err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) return err;
    uint8_t pk[32], sk[64];
    err = aktualino_store_load_ecu_key(pk, sk);
    if (err != ESP_OK) { aktualino_store_free_creds(&creds); return err; }

    akt_target_t inst;
    fill_current_installed(&inst, hardware_id);
    ESP_LOGW(TAG, "reporting FAILED install cid=%s (running image unchanged)",
             correlation_id ? correlation_id : "(none)");
    err = post_manifest(&creds, NULL, pk, sk, &inst,
                        (correlation_id && correlation_id[0]) ? correlation_id : NULL,
                        false, NULL);
    aktualino_store_free_creds(&creds);
    return err;
}
