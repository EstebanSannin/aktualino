/*
 * akt_uptane.c — Uptane role verification, target selection, manifest builder.
 * Portable (host + target); see akt_uptane.h. T1.3 + T1.4.
 */
#include "akt_uptane.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- ISO-8601 UTC -> unix time (portable, no timegm dependency) --- */
static long long days_from_civil(long y, unsigned m, unsigned d)
{
    /* Howard Hinnant's civil-from-days, inverse. Valid for the Gregorian
     * calendar; days since 1970-01-01. */
    y -= (m <= 2);
    long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097LL + (long long)doe - 719468;
}

int akt_parse_iso8601_utc(const char *s, time_t *out)
{
    if (!s || !out) return -1;
    int Y, M, D, h, mi, se;
    /* Accept "YYYY-MM-DDTHH:MM:SSZ" (trailing Z or nothing / fractional
     * seconds are tolerated by ignoring anything after the seconds). */
    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d", &Y, &M, &D, &h, &mi, &se) != 6)
        return -1;
    if (M < 1 || M > 12 || D < 1 || D > 31) return -1;
    long long days = days_from_civil(Y, (unsigned)M, (unsigned)D);
    long long secs = days * 86400LL + (long long)h * 3600 + mi * 60 + se;
    *out = (time_t)secs;
    return 0;
}

/* ---- helpers ----------------------------------------------------- */
static const cJSON *obj_get(const cJSON *o, const char *k)
{
    return cJSON_GetObjectItemCaseSensitive(o, k);
}

/* Find the signature entry for a given keyid inside envelope.signatures. */
static const cJSON *find_sig(const cJSON *signatures, const char *keyid)
{
    const cJSON *sig;
    cJSON_ArrayForEach(sig, signatures) {
        const cJSON *k = obj_get(sig, "keyid");
        if (cJSON_IsString(k) && strcmp(k->valuestring, keyid) == 0) return sig;
    }
    return NULL;
}

/* ---- role verify ------------------------------------------------- */
int akt_verify_role(const cJSON *root_signed, const char *role_name,
                    const cJSON *envelope, time_t now, long min_version)
{
    if (!root_signed || !role_name || !envelope) return AKT_ERR_PARSE;

    const cJSON *roles = obj_get(root_signed, "roles");
    const cJSON *keys  = obj_get(root_signed, "keys");
    if (!cJSON_IsObject(roles) || !cJSON_IsObject(keys)) return AKT_ERR_PARSE;

    const cJSON *role = obj_get(roles, role_name);
    if (!cJSON_IsObject(role)) return AKT_ERR_NO_ROLE;

    const cJSON *keyids   = obj_get(role, "keyids");
    const cJSON *thresh_j = obj_get(role, "threshold");
    if (!cJSON_IsArray(keyids) || !cJSON_IsNumber(thresh_j)) return AKT_ERR_PARSE;
    long threshold = (long)thresh_j->valuedouble;

    const cJSON *signed_obj  = obj_get(envelope, "signed");
    const cJSON *signatures  = obj_get(envelope, "signatures");
    if (!cJSON_IsObject(signed_obj) || !cJSON_IsArray(signatures)) return AKT_ERR_PARSE;

    /* Canonical bytes of the `signed` sub-object == the signature input. */
    size_t canon_len = 0;
    char *canon = akt_canonical_json(signed_obj, &canon_len);
    if (!canon) return AKT_ERR_INTERNAL;

    int rc = AKT_OK;
    long valid_count = 0;

    /* Count distinct authorized keyids that carry a valid signature. */
    const cJSON *kid;
    cJSON_ArrayForEach(kid, keyids) {
        if (!cJSON_IsString(kid)) continue;
        const cJSON *sig_entry = find_sig(signatures, kid->valuestring);
        if (!sig_entry) continue;
        const cJSON *key_obj = obj_get(keys, kid->valuestring);
        if (!cJSON_IsObject(key_obj)) continue;

        const cJSON *sig_b64 = obj_get(sig_entry, "sig");
        if (!cJSON_IsString(sig_b64)) continue;

        akt_pubkey_t pk;
        if (akt_parse_tuf_key(key_obj, &pk) != 0) continue;

        uint8_t sig[512];
        size_t sig_len = 0;
        if (akt_base64_decode(sig_b64->valuestring, sig, sizeof(sig), &sig_len) == 0) {
            if (akt_verify_with_pubkey(&pk, canon, canon_len, sig, sig_len))
                valid_count++;
        }
        akt_pubkey_free(&pk);
    }

    if (!(threshold > 0 && valid_count >= threshold)) {
        rc = AKT_ERR_THRESHOLD;
        goto done;
    }

    /* Expiry (SPEC §7.2 / §9). */
    if (now != 0) {
        const cJSON *exp = obj_get(signed_obj, "expires");
        if (!cJSON_IsString(exp)) { rc = AKT_ERR_PARSE; goto done; }
        time_t exp_t;
        if (akt_parse_iso8601_utc(exp->valuestring, &exp_t) != 0) { rc = AKT_ERR_PARSE; goto done; }
        if (exp_t <= now) { rc = AKT_ERR_EXPIRED; goto done; }
    }

    /* Version monotonicity (metadata rollback protection). */
    {
        const cJSON *ver = obj_get(signed_obj, "version");
        long v = cJSON_IsNumber(ver) ? (long)ver->valuedouble : 0;
        if (v < min_version) { rc = AKT_ERR_ROLLBACK; goto done; }
    }

done:
    free(canon);
    return rc;
}

int akt_verify_role_bytes(const char *root_signed_json, size_t root_len,
                          const char *role_name,
                          const char *envelope_json, size_t env_len,
                          time_t now, long min_version)
{
    cJSON *root = cJSON_ParseWithLength(root_signed_json, root_len);
    cJSON *env  = cJSON_ParseWithLength(envelope_json, env_len);
    int rc = AKT_ERR_PARSE;
    if (root && env)
        rc = akt_verify_role(root, role_name, env, now, min_version);
    cJSON_Delete(root);
    cJSON_Delete(env);
    return rc;
}

/* ---- Director target selection ----------------------------------- */
static bool hwid_matches(const cJSON *custom, const char *hwid)
{
    if (!cJSON_IsObject(custom)) return false;
    const cJSON *hi = obj_get(custom, "hardwareIdentifier");
    if (cJSON_IsString(hi) && strcmp(hi->valuestring, hwid) == 0) return true;
    /* Also accept a hardwareIds[] array (some director shapes). */
    const cJSON *arr = obj_get(custom, "hardwareIds");
    if (cJSON_IsArray(arr)) {
        const cJSON *e;
        cJSON_ArrayForEach(e, arr) {
            if (cJSON_IsString(e) && strcmp(e->valuestring, hwid) == 0) return true;
        }
    }
    /*
     * The Director targets shape: custom.ecuIdentifiers = { "<ecuSerial>": {
     * "hardwareId": "<hwid>" }, ... }. Match the per-ECU hardwareId here.
     */
    const cJSON *ecu_ids = obj_get(custom, "ecuIdentifiers");
    if (cJSON_IsObject(ecu_ids)) {
        const cJSON *ent;
        cJSON_ArrayForEach(ent, ecu_ids) {
            const cJSON *h = obj_get(ent, "hardwareId");
            if (cJSON_IsString(h) && strcmp(h->valuestring, hwid) == 0) return true;
        }
    }
    return false;
}

/*
 * The correlation id of the current assignment lives at the Director targets
 * `signed.custom.correlationId` (DeviceTargetsCustom), e.g.
 * "urn:here-ota:mtu:<uuid>". Copies it to `out` (NUL-terminated) and returns
 * AKT_OK, or AKT_ERR_NO_TARGET when no assignment/correlation id is present.
 */
int akt_targets_correlation_id(const cJSON *targets_signed, char *out, size_t cap)
{
    if (!targets_signed || !out || cap == 0) return AKT_ERR_PARSE;
    out[0] = '\0';
    const cJSON *custom = obj_get(targets_signed, "custom");
    if (!cJSON_IsObject(custom)) return AKT_ERR_NO_TARGET;
    const cJSON *cid = obj_get(custom, "correlationId");
    if (!cJSON_IsString(cid) || !cid->valuestring[0]) return AKT_ERR_NO_TARGET;
    snprintf(out, cap, "%s", cid->valuestring);
    return AKT_OK;
}

/* ---- image-repo meta-hash chain + cross-repo target matching ------ */

int akt_verify_meta_link(const cJSON *referrer_signed, const char *meta_key,
                         const uint8_t *file_bytes, size_t file_len,
                         long ref_version)
{
    if (!referrer_signed || !meta_key || !file_bytes) return AKT_ERR_PARSE;

    const cJSON *meta = obj_get(referrer_signed, "meta");
    if (!cJSON_IsObject(meta)) return AKT_ERR_PARSE;
    const cJSON *entry = obj_get(meta, meta_key);
    if (!cJSON_IsObject(entry)) return AKT_ERR_PARSE;

    const cJSON *hashes = obj_get(entry, "hashes");
    const cJSON *len_j  = obj_get(entry, "length");
    if (!cJSON_IsObject(hashes) || !cJSON_IsNumber(len_j)) return AKT_ERR_PARSE;
    const cJSON *sha_j = obj_get(hashes, "sha256");
    if (!cJSON_IsString(sha_j)) return AKT_ERR_PARSE;

    /* length must match the exact served byte count. */
    if ((size_t)len_j->valuedouble != file_len) return AKT_ERR_CROSSREPO;

    /* sha256 of the RAW served bytes must equal the pinned hash. */
    uint8_t want[32], got[32];
    size_t n = 0;
    if (akt_hex_decode(sha_j->valuestring, want, sizeof(want), &n) != 0 || n != 32)
        return AKT_ERR_PARSE;
    if (akt_sha256(file_bytes, file_len, got) != 0) return AKT_ERR_INTERNAL;
    if (memcmp(want, got, 32) != 0) return AKT_ERR_CROSSREPO;

    /* version pin (defence against a mixed-version chain). */
    if (ref_version >= 0) {
        const cJSON *ver = obj_get(entry, "version");
        long v = cJSON_IsNumber(ver) ? (long)ver->valuedouble : -1;
        if (v != ref_version) return AKT_ERR_CROSSREPO;
    }
    return AKT_OK;
}

int akt_image_target_matches(const cJSON *image_targets_signed,
                             const akt_target_t *dir)
{
    if (!image_targets_signed || !dir) return AKT_ERR_PARSE;
    const cJSON *targets = obj_get(image_targets_signed, "targets");
    if (!cJSON_IsObject(targets)) return AKT_ERR_PARSE;

    /* Same filepath key the Director assigned. */
    const cJSON *t = obj_get(targets, dir->filepath);
    if (!cJSON_IsObject(t)) return AKT_ERR_NO_TARGET;   /* Director-only target */

    const cJSON *length = obj_get(t, "length");
    const cJSON *hashes = obj_get(t, "hashes");
    if (!cJSON_IsNumber(length) || !cJSON_IsObject(hashes)) return AKT_ERR_PARSE;
    const cJSON *sha = obj_get(hashes, "sha256");
    if (!cJSON_IsString(sha)) return AKT_ERR_PARSE;

    if ((size_t)length->valuedouble != dir->length) return AKT_ERR_CROSSREPO;

    uint8_t img_sha[32];
    size_t n = 0;
    if (akt_hex_decode(sha->valuestring, img_sha, sizeof(img_sha), &n) != 0 || n != 32)
        return AKT_ERR_PARSE;
    if (memcmp(img_sha, dir->sha256, 32) != 0) return AKT_ERR_CROSSREPO;
    return AKT_OK;
}

int akt_select_target(const cJSON *targets_signed, const char *hwid, akt_target_t *out)
{
    if (!targets_signed || !hwid || !out) return AKT_ERR_PARSE;
    const cJSON *targets = obj_get(targets_signed, "targets");
    if (!cJSON_IsObject(targets)) return AKT_ERR_PARSE;

    const cJSON *t;
    cJSON_ArrayForEach(t, targets) {
        const cJSON *custom = obj_get(t, "custom");
        if (!hwid_matches(custom, hwid)) continue;

        const char *filepath = t->string;
        const cJSON *length   = obj_get(t, "length");
        const cJSON *hashes   = obj_get(t, "hashes");
        if (!filepath || !cJSON_IsNumber(length) || !cJSON_IsObject(hashes))
            return AKT_ERR_PARSE;
        const cJSON *sha = obj_get(hashes, "sha256");
        if (!cJSON_IsString(sha)) return AKT_ERR_PARSE;

        if (strstr(filepath, "..") != NULL) return AKT_ERR_PARSE; /* path safety */

        memset(out, 0, sizeof(*out));
        snprintf(out->filepath, sizeof(out->filepath), "%s", filepath);
        out->length = (size_t)length->valuedouble;
        size_t n = 0;
        if (akt_hex_decode(sha->valuestring, out->sha256, 32, &n) != 0 || n != 32)
            return AKT_ERR_PARSE;
        const cJSON *ver = cJSON_IsObject(custom) ? obj_get(custom, "version") : NULL;
        out->version = cJSON_IsNumber(ver) ? (long)ver->valuedouble : 0;
        return AKT_OK;
    }
    return AKT_ERR_NO_TARGET;
}

/* ---- manifest builder (V3, double Ed25519 sign) ------------------ */

/* Sign `signed_obj`, returning a freshly-built envelope { signatures, signed }.
 * The passed signed_obj is consumed (attached to the envelope). */
static cJSON *sign_envelope(cJSON *signed_obj,
                            const uint8_t pk[32], const uint8_t sk[64])
{
    size_t canon_len = 0;
    char *canon = akt_canonical_json(signed_obj, &canon_len);
    if (!canon) { cJSON_Delete(signed_obj); return NULL; }

    uint8_t sig[64];
    if (akt_sign_ed25519(sk, canon, canon_len, sig) != 0) {
        free(canon); cJSON_Delete(signed_obj); return NULL;
    }
    free(canon);

    char keyid[65];
    char sig_b64[128];
    if (akt_keyid_ed25519(pk, keyid) != 0 ||
        akt_base64_encode(sig, sizeof(sig), sig_b64, sizeof(sig_b64)) != 0) {
        cJSON_Delete(signed_obj); return NULL;
    }

    cJSON *env = cJSON_CreateObject();
    cJSON *sigs = cJSON_CreateArray();
    cJSON *sig_entry = cJSON_CreateObject();
    if (!env || !sigs || !sig_entry) {
        cJSON_Delete(env); cJSON_Delete(sigs); cJSON_Delete(sig_entry);
        cJSON_Delete(signed_obj); return NULL;
    }
    cJSON_AddStringToObject(sig_entry, "keyid", keyid);
    cJSON_AddStringToObject(sig_entry, "method", "ed25519");
    cJSON_AddStringToObject(sig_entry, "sig", sig_b64);
    cJSON_AddItemToArray(sigs, sig_entry);
    cJSON_AddItemToObject(env, "signatures", sigs);
    cJSON_AddItemToObject(env, "signed", signed_obj);
    return env;
}

/*
 * Build the installation_report object (SPEC Appendix A; the OTA-Connect director
 * keys DeviceUpdateCompleted off report.result + report.correlation_id).
 * `success` controls result.code/success; `ecu_serial` scopes the per-ECU item.
 * Caller attaches the returned object.
 */
static cJSON *build_installation_report(const char *correlation_id,
                                        const char *ecu_serial, bool success)
{
    const char *code = success ? "OK" : "INSTALL_FAILED";
    const char *desc = success ? "Installing package was successful"
                               : "Installation failed";
    const char *dev_desc = success ? "Device has been successfully installed"
                                   : "Device installation failed";

    cJSON *ir     = cJSON_CreateObject();
    cJSON *report = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();
    cJSON *items  = cJSON_CreateArray();
    cJSON *item   = cJSON_CreateObject();
    cJSON *ires   = cJSON_CreateObject();
    if (!ir || !report || !result || !items || !item || !ires) {
        cJSON_Delete(ir); cJSON_Delete(report); cJSON_Delete(result);
        cJSON_Delete(items); cJSON_Delete(item); cJSON_Delete(ires);
        return NULL;
    }

    cJSON_AddStringToObject(result, "code", code);
    cJSON_AddStringToObject(result, "description", dev_desc);
    cJSON_AddBoolToObject(result, "success", success);

    cJSON_AddStringToObject(ires, "code", code);
    cJSON_AddStringToObject(ires, "description", desc);
    cJSON_AddBoolToObject(ires, "success", success);
    cJSON_AddStringToObject(item, "ecu", ecu_serial);
    cJSON_AddItemToObject(item, "result", ires);
    cJSON_AddItemToArray(items, item);

    cJSON_AddStringToObject(report, "correlation_id", correlation_id);
    cJSON_AddItemToObject(report, "items", items);
    cJSON_AddStringToObject(report, "raw_report",
                            success ? "Installation successful"
                                    : "Installation failed");
    cJSON_AddItemToObject(report, "result", result);

    cJSON_AddStringToObject(ir, "content_type",
                            "application/vnd.com.here.otac.installationReport.v1");
    cJSON_AddItemToObject(ir, "report", report);
    return ir;
}

char *akt_build_manifest_report(const char *primary_ecu_serial,
                                const akt_target_t *installed,
                                const char *attacks_detected,
                                const char *correlation_id, bool success,
                                const uint8_t ecu_pk[32], const uint8_t ecu_sk[64],
                                size_t *out_len);

char *akt_build_manifest(const char *primary_ecu_serial,
                         const akt_target_t *installed,
                         const char *attacks_detected,
                         const uint8_t ecu_pk[32], const uint8_t ecu_sk[64],
                         size_t *out_len)
{
    /* installation_report = null (no update to report). */
    return akt_build_manifest_report(primary_ecu_serial, installed,
                                     attacks_detected, NULL, true,
                                     ecu_pk, ecu_sk, out_len);
}

/*
 * Build one ECU's nested EcuManifest SignedPayload: the `signed` object
 * (installed_image + ecu_serial + attacks_detected) signed by (pk, sk). Shared
 * by the primary and the optional secondary (which reuses the same key). Returns
 * a signed envelope (caller attaches) or NULL.
 */
static cJSON *build_ecu_manifest_env(const char *ecu_serial,
                                     const akt_target_t *installed,
                                     const char *attacks_detected,
                                     const uint8_t pk[32], const uint8_t sk[64])
{
    char sha_hex[65];
    if (akt_hex_encode(installed->sha256, 32, sha_hex, sizeof(sha_hex)) != 0)
        return NULL;
    cJSON *inner = cJSON_CreateObject();
    if (!inner) return NULL;
    cJSON *img    = cJSON_CreateObject();
    cJSON *finfo  = cJSON_CreateObject();
    cJSON *hashes = cJSON_CreateObject();
    cJSON_AddStringToObject(hashes, "sha256", sha_hex);
    cJSON_AddItemToObject(finfo, "hashes", hashes);
    cJSON_AddNumberToObject(finfo, "length", (double)installed->length);
    cJSON_AddStringToObject(img, "filepath", installed->filepath);
    cJSON_AddItemToObject(img, "fileinfo", finfo);
    cJSON_AddItemToObject(inner, "installed_image", img);
    cJSON_AddStringToObject(inner, "ecu_serial", ecu_serial);
    cJSON_AddStringToObject(inner, "attacks_detected",
                            attacks_detected ? attacks_detected : "");
    return sign_envelope(inner, pk, sk);
}

char *akt_build_manifest_report(const char *primary_ecu_serial,
                                const akt_target_t *installed,
                                const char *attacks_detected,
                                const char *correlation_id, bool success,
                                const uint8_t ecu_pk[32], const uint8_t ecu_sk[64],
                                size_t *out_len)
{
    return akt_build_manifest_ex(primary_ecu_serial, installed, attacks_detected,
                                 correlation_id, success, NULL,
                                 ecu_pk, ecu_sk, out_len);
}

char *akt_build_manifest_ex(const char *primary_ecu_serial,
                            const akt_target_t *installed,
                            const char *attacks_detected,
                            const char *correlation_id, bool success,
                            const akt_secondary_t *secondary,
                            const uint8_t ecu_pk[32], const uint8_t ecu_sk[64],
                            size_t *out_len)
{
    if (!primary_ecu_serial || !installed) return NULL;
    if (secondary && !secondary->ecu_serial) return NULL;

    /* ---- primary's nested EcuManifest ---- */
    cJSON *inner_env = build_ecu_manifest_env(primary_ecu_serial, installed,
                                              attacks_detected, ecu_pk, ecu_sk);
    if (!inner_env) return NULL;

    /* ---- optional secondary's nested EcuManifest (same key) ---- */
    cJSON *sec_env = NULL;
    if (secondary) {
        sec_env = build_ecu_manifest_env(secondary->ecu_serial,
                                         &secondary->installed,
                                         secondary->attacks_detected,
                                         ecu_pk, ecu_sk);
        if (!sec_env) { cJSON_Delete(inner_env); return NULL; }
    }

    /* ---- outer manifest `signed` ---- */
    cJSON *outer = cJSON_CreateObject();
    if (!outer) { cJSON_Delete(inner_env); cJSON_Delete(sec_env); return NULL; }
    cJSON_AddStringToObject(outer, "primary_ecu_serial", primary_ecu_serial);
    cJSON *evm = cJSON_CreateObject();
    cJSON_AddItemToObject(evm, primary_ecu_serial, inner_env); /* nested SignedPayload */
    if (sec_env)
        cJSON_AddItemToObject(evm, secondary->ecu_serial, sec_env);
    cJSON_AddItemToObject(outer, "ecu_version_manifests", evm);
    if (correlation_id && correlation_id[0]) {
        cJSON *ir = build_installation_report(correlation_id,
                                              primary_ecu_serial, success);
        if (!ir) { cJSON_Delete(outer); return NULL; }
        cJSON_AddItemToObject(outer, "installation_report", ir);
    } else {
        cJSON_AddItemToObject(outer, "installation_report", cJSON_CreateNull());
    }

    cJSON *outer_env = sign_envelope(outer, ecu_pk, ecu_sk);
    if (!outer_env) return NULL;

    char *json = cJSON_PrintUnformatted(outer_env);
    cJSON_Delete(outer_env);
    if (!json) return NULL;
    if (out_len) *out_len = strlen(json);
    return json;
}
