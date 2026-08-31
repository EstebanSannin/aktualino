/*
 * aktualino_core — orchestrator: state names + Phase-2 Director poll/verify loop.
 *
 * Phase 2 runs the (host-unit-tested) portable Uptane core (akt_uptane /
 * akt_crypto) against the live Torizon Cloud Director over mTLS:
 *   - trust anchor: an embedded root.json (shipped in firmware, TOFU-free) is
 *     checked for self-consistency and persisted to NVS on first boot; later
 *     boots load the persisted (possibly rotation-advanced) root;
 *   - each poll walks the root-rotation chain forward (/director/{N}.root.json),
 *     each new root signed by the previous root (threshold) AND by itself;
 *   - timestamp/snapshot/targets are fetched and, for each: canonical(signed) is
 *     re-derived, signatures are checked against the current root's role keyids +
 *     threshold, `expires` is a hard gate against SNTP time, and version
 *     monotonicity is enforced against NVS (downgrades rejected, new versions
 *     persisted);
 *   - a target for our hardware id is selected. Phase 2 assigns none, so the
 *     correct outcome is "no update assigned — up to date".
 *
 * Image-repo (/repo) cross-check is Phase 4; this file is Director-only.
 */
#include "aktualino_core.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_log.h"

#include "cJSON.h"
#include "akt_uptane.h"
#include "akt_crypto.h"

#include "aktualino_store.h"
#include "aktualino_net.h"
#include "aktualino_ota.h"

static const char *TAG = "akt_core";

/* Stored trusted-root blob names (aktualino_store NS_TUF). */
#define ROOT_BLOB_NAME     "director/root"
#define IMG_ROOT_BLOB_NAME "image/root"
/* Generous read buffer for the stored root (a root is a few KB). */
#define ROOT_READ_CAP  8192

/*
 * A "repo context" parametrizes the shared root-rotation walk + role-verify code
 * over the two Uptane repositories. The Director path (/director) is byte-
 * UNSTABLE per request (it regenerates timestamp/snapshot/targets), so its chain
 * meta-hashes cannot be cross-checked device-side; the Image repo (/repo,
 * reposerver user_repo) is byte-STABLE, so its full timestamp->snapshot->targets
 * meta-hash chain holds and IS verified (check_meta_chain). Both repos keep
 * DISTINCT NVS blob + version keys so their versions never collide.
 */
typedef struct {
    const char *name;         /* "Director" | "Image" (logs)                */
    const char *path_prefix;  /* "/director" | "/repo"                      */
    const char *root_blob;    /* NVS metadata blob name for the trusted root*/
    const char *vt_root;      /* NVS version tag for root                    */
    const char *vt_ts;        /* ... timestamp                              */
    const char *vt_snap;      /* ... snapshot                               */
    const char *vt_tgt;       /* ... targets                                */
} akt_repo_t;

static const akt_repo_t REPO_DIRECTOR = {
    .name = "Director", .path_prefix = "/director", .root_blob = ROOT_BLOB_NAME,
    .vt_root = "root", .vt_ts = "timestamp", .vt_snap = "snapshot", .vt_tgt = "targets",
};
static const akt_repo_t REPO_IMAGE = {
    .name = "Image", .path_prefix = "/repo", .root_blob = IMG_ROOT_BLOB_NAME,
    .vt_root = "img_root", .vt_ts = "img_ts", .vt_snap = "img_snap", .vt_tgt = "img_tgt",
};

const char *aktualino_state_name(aktualino_state_t st)
{
    switch (st) {
    case AKT_STATE_BOOT:            return "BOOT";
    case AKT_STATE_TIME_SYNC:       return "TIME_SYNC";
    case AKT_STATE_PROVISION:       return "PROVISION";
    case AKT_STATE_POLL_DIRECTOR:   return "POLL_DIRECTOR";
    case AKT_STATE_VERIFY_METADATA: return "VERIFY_METADATA";
    case AKT_STATE_DOWNLOAD:        return "DOWNLOAD";
    case AKT_STATE_VERIFY_IMAGE:    return "VERIFY_IMAGE";
    case AKT_STATE_INSTALL:         return "INSTALL";
    case AKT_STATE_REBOOT:          return "REBOOT";
    case AKT_STATE_CONFIRM:         return "CONFIRM";
    case AKT_STATE_ROLLBACK:        return "ROLLBACK";
    case AKT_STATE_REPORT:          return "REPORT";
    case AKT_STATE_IDLE:            return "IDLE";
    case AKT_STATE_ERROR:           return "ERROR";
    default:                        return "UNKNOWN";
    }
}

aktualino_state_t aktualino_transition(aktualino_state_t prev,
                                       aktualino_state_t next)
{
    ESP_LOGI(TAG, "state: %s -> %s",
             aktualino_state_name(prev), aktualino_state_name(next));
    return next;
}

/* ------------------------------------------------------------------ *
 * Small helpers
 * ------------------------------------------------------------------ */

static const char *akt_err_name(int rc)
{
    switch (rc) {
    case AKT_OK:            return "OK";
    case AKT_ERR_PARSE:     return "PARSE";
    case AKT_ERR_NO_ROLE:   return "NO_ROLE";
    case AKT_ERR_THRESHOLD: return "THRESHOLD(bad/insufficient sig)";
    case AKT_ERR_EXPIRED:   return "EXPIRED";
    case AKT_ERR_ROLLBACK:  return "ROLLBACK(downgrade)";
    case AKT_ERR_NO_TARGET: return "NO_TARGET";
    default:                return "INTERNAL";
    }
}

static esp_err_t map_akt_err(int rc)
{
    switch (rc) {
    case AKT_OK:            return ESP_OK;
    case AKT_ERR_NO_ROLE:   return ESP_ERR_NOT_FOUND;
    case AKT_ERR_THRESHOLD: return ESP_ERR_INVALID_CRC;
    case AKT_ERR_EXPIRED:   return ESP_ERR_TIMEOUT;
    case AKT_ERR_ROLLBACK:  return ESP_ERR_INVALID_VERSION;
    case AKT_ERR_NO_TARGET: return ESP_ERR_NOT_FOUND;
    default:                return ESP_FAIL;
    }
}

/* signed.version as int32 (0 if absent). */
static int32_t signed_version(const cJSON *signed_obj)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(signed_obj, "version");
    return cJSON_IsNumber(v) ? (int32_t)v->valuedouble : 0;
}

/*
 * Buffered mTLS GET of a director path. On ESP_OK, *body is a malloc'd
 * NUL-terminated response (caller frees) and *status the HTTP code.
 */
static esp_err_t director_get(const aktualino_creds_t *creds, const char *path,
                              char **body, size_t *body_len, int *status)
{
    char url[320];
    snprintf(url, sizeof(url), "%s%s", creds->gateway_url, path);
    aktualino_net_req_cfg_t cfg = {
        .url = url,
        .method = "GET",
        .cacert_pem = creds->cacert_pem,
        .client_cert_pem = creds->client_cert_pem,
        .client_key_pem = creds->client_key_pem,
        .timeout_ms = 20000,
    };
    return aktualino_net_request(&cfg, body, body_len, status);
}

/* ------------------------------------------------------------------ *
 * Trust anchor
 * ------------------------------------------------------------------ */

static esp_err_t trust_anchor_init_repo(const akt_repo_t *repo,
                                        const char *embedded_root_json,
                                        size_t len, int64_t now)
{
    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    /* Already have a persisted trusted root? Load + report its version. */
    char *buf = malloc(ROOT_READ_CAP);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t got = 0;
    esp_err_t rd = aktualino_store_get_metadata(repo->root_blob, buf, ROOT_READ_CAP, &got);
    if (rd == ESP_OK && got > 0) {
        cJSON *env = cJSON_ParseWithLength(buf, got);
        int32_t v = 0;
        int rc = AKT_ERR_PARSE;
        if (env) {
            const cJSON *signed_obj = cJSON_GetObjectItemCaseSensitive(env, "signed");
            if (cJSON_IsObject(signed_obj)) {
                v = signed_version(signed_obj);
                /* Self-verify the persisted root against the 'root'-role keys it
                 * itself lists (now=0 skips expiry). This validates a
                 * provisioning-seeded anchor on-device (SPEC §6.1: Torizon Cloud
                 * provisioning seeds the initial NVS root from device.zip) and
                 * guards against a corrupt/tampered NVS anchor. The signature
                 * method (ed25519 / rsassa-pss-sha256) is dispatched from the
                 * root's own key entries. */
                rc = akt_verify_role(signed_obj, "root", env, (time_t)0, 0);
            }
        }
        cJSON_Delete(env);
        free(buf);
        if (rc != AKT_OK) {
            ESP_LOGE(TAG, "trust anchor: persisted %s root self-verify FAILED: %s",
                     repo->name, akt_err_name(rc));
            return map_akt_err(rc);
        }
        ESP_LOGI(TAG, "trust anchor: using persisted %s root v%ld (self-verify OK)",
                 repo->name, (long)v);
        return ESP_OK;
    }
    free(buf);

    /* First boot: bootstrap from the embedded root (shipped in firmware). */
    if (!embedded_root_json || len == 0) {
        ESP_LOGE(TAG, "trust anchor: no embedded %s root available", repo->name);
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *env = cJSON_ParseWithLength(embedded_root_json, len);
    if (!env) {
        ESP_LOGE(TAG, "trust anchor: embedded %s root is not valid JSON", repo->name);
        return ESP_ERR_INVALID_ARG;
    }
    const cJSON *signed_obj = cJSON_GetObjectItemCaseSensitive(env, "signed");
    if (!cJSON_IsObject(signed_obj)) {
        ESP_LOGE(TAG, "trust anchor: embedded %s root missing 'signed'", repo->name);
        cJSON_Delete(env);
        return ESP_ERR_INVALID_ARG;
    }
    int32_t v = signed_version(signed_obj);

    /* Self-consistency: the embedded root must be signed by a threshold of the
     * keys it itself lists for the 'root' role. now=0 skips the anchor's own
     * expiry so a long-lived anchor bootstraps regardless. */
    int rc = akt_verify_role(signed_obj, "root", env, (time_t)now, 0);
    if (rc != AKT_OK) {
        ESP_LOGE(TAG, "trust anchor: embedded %s root self-verify FAILED: %s",
                 repo->name, akt_err_name(rc));
        cJSON_Delete(env);
        return map_akt_err(rc);
    }
    cJSON_Delete(env);

    err = aktualino_store_put_metadata(repo->root_blob, embedded_root_json, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "trust anchor: %s persist failed: %s",
                 repo->name, esp_err_to_name(err));
        return err;
    }
    aktualino_store_set_meta_version(repo->vt_root, v);
    ESP_LOGI(TAG, "trust anchor: embedded %s root v%ld verified "
                  "(self-signed threshold) and pinned to NVS",
             repo->name, (long)v);
    return ESP_OK;
}

esp_err_t aktualino_core_trust_anchor_init(const char *embedded_root_json,
                                           size_t len, int64_t now)
{
    return trust_anchor_init_repo(&REPO_DIRECTOR, embedded_root_json, len, now);
}

esp_err_t aktualino_core_image_trust_anchor_init(const char *embedded_root_json,
                                                 size_t len, int64_t now)
{
    return trust_anchor_init_repo(&REPO_IMAGE, embedded_root_json, len, now);
}

/* ------------------------------------------------------------------ *
 * Root-rotation walk
 * ------------------------------------------------------------------ */

/*
 * Walk /director/{N+1}.root.json forward from the current trusted root. On
 * return *root_env is the (possibly advanced) trusted root envelope (caller
 * cJSON_Delete's it) and *root_signed points inside it. Returns ESP_OK on a
 * clean walk (including "no rotation"); an error if a rotation link is invalid.
 */
static esp_err_t walk_root_rotation(const aktualino_creds_t *creds,
                                    const akt_repo_t *repo, int64_t now,
                                    cJSON **root_env_out, int32_t *version_out)
{
    /* Load the current trusted root from NVS. */
    char *buf = malloc(ROOT_READ_CAP);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t got = 0;
    esp_err_t err = aktualino_store_get_metadata(repo->root_blob, buf, ROOT_READ_CAP, &got);
    if (err != ESP_OK || got == 0) {
        free(buf);
        ESP_LOGE(TAG, "%s root walk: no trusted root in NVS (%s)",
                 repo->name, esp_err_to_name(err));
        return (err == ESP_OK) ? ESP_ERR_NOT_FOUND : err;
    }
    cJSON *cur_env = cJSON_ParseWithLength(buf, got);
    free(buf);
    if (!cur_env) return ESP_ERR_INVALID_STATE;
    cJSON *cur_signed = cJSON_GetObjectItemCaseSensitive(cur_env, "signed");
    int32_t N = signed_version(cur_signed);

    /* Learn the latest available root version. */
    char root_path[48];
    snprintf(root_path, sizeof(root_path), "%s/root.json", repo->path_prefix);
    char *latest = NULL; size_t llen = 0; int lstatus = 0;
    err = director_get(creds, root_path, &latest, &llen, &lstatus);
    if (err != ESP_OK || lstatus != 200 || !latest) {
        ESP_LOGW(TAG, "%s root walk: GET root.json failed (err=%s http=%d) — "
                      "keeping trusted root v%ld", repo->name,
                 esp_err_to_name(err), lstatus, (long)N);
        free(latest);
        *root_env_out = cur_env; *version_out = N;
        return ESP_OK;  /* transient: proceed with the pinned root */
    }
    cJSON *latest_env = cJSON_ParseWithLength(latest, llen);
    free(latest);
    int32_t L = latest_env ? signed_version(cJSON_GetObjectItemCaseSensitive(latest_env, "signed")) : 0;
    cJSON_Delete(latest_env);

    if (L < N) {
        ESP_LOGW(TAG, "%s root walk: SECURITY — server offered root v%ld < trusted v%ld; "
                      "rejecting downgrade, keeping v%ld", repo->name,
                 (long)L, (long)N, (long)N);
        *root_env_out = cur_env; *version_out = N;
        return ESP_OK;
    }
    if (L == N) {
        ESP_LOGI(TAG, "%s root walk: root up to date at v%ld (no rotation)",
                 repo->name, (long)N);
        *root_env_out = cur_env; *version_out = N;
        return ESP_OK;
    }

    /* L > N: verify each link N+1..L, previous-signed AND self-signed. */
    for (int32_t i = N + 1; i <= L; i++) {
        char path[48];
        snprintf(path, sizeof(path), "%s/%ld.root.json", repo->path_prefix, (long)i);
        char *rb = NULL; size_t rlen = 0; int rstatus = 0;
        err = director_get(creds, path, &rb, &rlen, &rstatus);
        if (err != ESP_OK || rstatus != 200 || !rb) {
            ESP_LOGE(TAG, "%s root walk: GET %s failed (err=%s http=%d)",
                     repo->name, path, esp_err_to_name(err), rstatus);
            free(rb);
            cJSON_Delete(cur_env);
            return ESP_FAIL;
        }
        cJSON *new_env = cJSON_ParseWithLength(rb, rlen);
        if (!new_env) { free(rb); cJSON_Delete(cur_env); return ESP_ERR_INVALID_ARG; }
        cJSON *new_signed = cJSON_GetObjectItemCaseSensitive(new_env, "signed");

        /* signed by the PREVIOUS (currently trusted) root, version >= i. */
        int rc_prev = akt_verify_role(cur_signed, "root", new_env, (time_t)now, i);
        /* signed by ITSELF (the new key set authorizes itself). */
        int rc_self = akt_verify_role(new_signed, "root", new_env, (time_t)now, i);
        if (rc_prev != AKT_OK || rc_self != AKT_OK) {
            ESP_LOGE(TAG, "%s root walk: rotation v%ld->v%ld REJECTED "
                          "(prev-sig=%s self-sig=%s)", repo->name, (long)(i - 1), (long)i,
                     akt_err_name(rc_prev), akt_err_name(rc_self));
            free(rb);
            cJSON_Delete(new_env);
            cJSON_Delete(cur_env);
            return ESP_ERR_INVALID_CRC;
        }

        /* Adopt: persist the new root and advance. */
        aktualino_store_put_metadata(repo->root_blob, rb, rlen);
        aktualino_store_set_meta_version(repo->vt_root, i);
        free(rb);
        cJSON_Delete(cur_env);
        cur_env = new_env;
        cur_signed = new_signed;
        N = i;
        ESP_LOGW(TAG, "%s root walk: rotation adopted -> root now v%ld "
                      "(prev-signed + self-signed OK)", repo->name, (long)N);
    }

    *root_env_out = cur_env; *version_out = N;
    return ESP_OK;
}

/* ------------------------------------------------------------------ *
 * Verify one non-root role (timestamp/snapshot/targets).
 * ------------------------------------------------------------------ */
static esp_err_t verify_role_fetch(const aktualino_creds_t *creds,
                                   const akt_repo_t *repo,
                                   const cJSON *root_signed,
                                   const char *role, const char *vtag,
                                   int64_t now, int32_t *version_out,
                                   cJSON **signed_keep,
                                   char **raw_keep, size_t *raw_len_keep)
{
    if (signed_keep) *signed_keep = NULL;
    if (raw_keep) *raw_keep = NULL;
    if (raw_len_keep) *raw_len_keep = 0;
    char path[48];
    snprintf(path, sizeof(path), "%s/%s.json", repo->path_prefix, role);
    char *body = NULL; size_t blen = 0; int status = 0;
    esp_err_t err = director_get(creds, path, &body, &blen, &status);
    if (err != ESP_OK || status != 200 || !body) {
        ESP_LOGE(TAG, "%s %-9s: GET failed (err=%s http=%d)", repo->name, role,
                 esp_err_to_name(err), status);
        free(body);
        return (err != ESP_OK) ? err : ESP_FAIL;
    }
    cJSON *env = cJSON_ParseWithLength(body, blen);
    if (!env) {
        ESP_LOGE(TAG, "%s %-9s: response is not valid JSON", repo->name, role);
        free(body);
        return ESP_ERR_INVALID_ARG;
    }

    int32_t min_v = 0;
    aktualino_store_get_meta_version(vtag, &min_v);

    int rc = akt_verify_role(root_signed, role, env, (time_t)now, min_v);
    if (rc != AKT_OK) {
        ESP_LOGE(TAG, "%s %-9s: VERIFY FAIL — %s (min_version=%ld)",
                 repo->name, role, akt_err_name(rc), (long)min_v);
        cJSON_Delete(env);
        free(body);
        return map_akt_err(rc);
    }

    cJSON *signed_obj = cJSON_GetObjectItemCaseSensitive(env, "signed");
    int32_t v = signed_version(signed_obj);
    aktualino_store_set_meta_version(vtag, v);
    if (version_out) *version_out = v;
    /* Signature threshold met over canonical(signed); the actual primitive
     * (rsassa-pss-sha256 for Torizon Cloud RSA roots, or ed25519) is dispatched
     * per key from the trust-anchor root, so keep this line algorithm-agnostic. */
    ESP_LOGI(TAG, "%s %-9s: VERIFY PASS (signature threshold met, expiry OK, "
                  "version %ld >= stored %ld) — persisted",
             repo->name, role, (long)v, (long)min_v);

    /* Hand back the RAW served bytes when asked (image-repo meta-hash chain
     * hashes exactly these bytes; the reposerver's pinned hash is over them). */
    if (raw_keep) { *raw_keep = body; if (raw_len_keep) *raw_len_keep = blen; }
    else free(body);

    if (signed_keep) *signed_keep = env;   /* caller keeps the envelope alive */
    else cJSON_Delete(env);
    return ESP_OK;
}

/* ------------------------------------------------------------------ *
 * One Director poll cycle
 * ------------------------------------------------------------------ */
esp_err_t aktualino_core_poll_director(const char *hwid, int64_t now,
                                       aktualino_poll_result_t *out)
{
    aktualino_poll_result_t r;
    memset(&r, 0, sizeof(r));

    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    aktualino_creds_t creds;
    err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "poll: load_creds failed: %s", esp_err_to_name(err));
        return err;
    }

    /* 1) root-rotation walk. */
    cJSON *root_env = NULL;
    int32_t root_v = 0;
    err = walk_root_rotation(&creds, &REPO_DIRECTOR, now, &root_env, &root_v);
    if (err != ESP_OK) {
        aktualino_store_free_creds(&creds);
        return err;
    }
    cJSON *root_signed = cJSON_GetObjectItemCaseSensitive(root_env, "signed");
    cJSON *targets_env = NULL;
    r.root_version = root_v;

    /* 2) timestamp -> snapshot -> targets. */
    err = verify_role_fetch(&creds, &REPO_DIRECTOR, root_signed, "timestamp",
                            REPO_DIRECTOR.vt_ts, now,
                            &r.timestamp_version, NULL, NULL, NULL);
    if (err != ESP_OK) goto done;

    err = verify_role_fetch(&creds, &REPO_DIRECTOR, root_signed, "snapshot",
                            REPO_DIRECTOR.vt_snap, now,
                            &r.snapshot_version, NULL, NULL, NULL);
    if (err != ESP_OK) goto done;

    err = verify_role_fetch(&creds, &REPO_DIRECTOR, root_signed, "targets",
                            REPO_DIRECTOR.vt_tgt, now,
                            &r.targets_version, &targets_env, NULL, NULL);
    if (err != ESP_OK) goto done;

    /* 3) target selection for our hardware id. */
    {
        cJSON *targets_signed = cJSON_GetObjectItemCaseSensitive(targets_env, "signed");
        akt_target_t t;
        int rc = akt_select_target(targets_signed, hwid, &t);
        if (rc == AKT_OK) {
            r.target_assigned = true;
            snprintf(r.target_path, sizeof(r.target_path), "%s", t.filepath);
            r.target_length = t.length;
            memcpy(r.target_sha256, t.sha256, 32);
            akt_hex_encode(t.sha256, 32, r.target_sha256_hex, sizeof(r.target_sha256_hex));
            /* Assignment correlation id lives at targets signed.custom.correlationId. */
            if (akt_targets_correlation_id(targets_signed, r.correlation_id,
                                           sizeof(r.correlation_id)) != AKT_OK)
                r.correlation_id[0] = '\0';
            ESP_LOGW(TAG, "target ASSIGNED for %s: %s (len=%zu sha256=%s cid=%s)",
                     hwid, r.target_path, r.target_length, r.target_sha256_hex,
                     r.correlation_id[0] ? r.correlation_id : "(none)");
        } else if (rc == AKT_ERR_NO_TARGET) {
            r.target_assigned = false;
            ESP_LOGI(TAG, "no update assigned — up to date (no target for %s)", hwid);
        } else {
            ESP_LOGE(TAG, "target selection error: %s", akt_err_name(rc));
            err = map_akt_err(rc);
        }
    }
    cJSON_Delete(targets_env);

done:
    cJSON_Delete(root_env);
    aktualino_store_free_creds(&creds);
    if (err == ESP_OK && out) *out = r;
    return err;
}

/* ------------------------------------------------------------------ *
 * Phase 4a — Image-repo (user_repo) verification + cross-repo matching
 * ------------------------------------------------------------------ */

/*
 * Verify the byte-stable Image repo (/repo) end-to-end and hand back the
 * verified targets envelope (caller cJSON_Delete's *out_targets_env):
 *   - walk the image root-rotation chain (own trust anchor, own NVS keys),
 *   - verify timestamp/snapshot/targets (signature threshold, expiry, monotonic
 *     version) against the image root,
 *   - verify the FULL meta-hash chain over the RAW served bytes:
 *       timestamp.meta["snapshot.json"] pins snapshot.json, and
 *       snapshot.meta["targets.json"]   pins targets.json
 *     (sha256 + length + version). The reposerver's pinned hash is SHA-256 of
 *     exactly the served envelope bytes, so we hash the bytes as received.
 */
esp_err_t aktualino_core_verify_image_repo(int64_t now, cJSON **out_targets_env)
{
    if (out_targets_env) *out_targets_env = NULL;

    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    aktualino_creds_t creds;
    err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "image: load_creds failed: %s", esp_err_to_name(err));
        return err;
    }

    cJSON *root_env = NULL, *ts_env = NULL, *snap_env = NULL, *tgt_env = NULL;
    char *snap_raw = NULL, *tgt_raw = NULL;
    size_t snap_len = 0, tgt_len = 0;
    int32_t root_v = 0, ts_v = 0, snap_v = 0, tgt_v = 0;

    err = walk_root_rotation(&creds, &REPO_IMAGE, now, &root_env, &root_v);
    if (err != ESP_OK) goto cleanup;
    cJSON *root_signed = cJSON_GetObjectItemCaseSensitive(root_env, "signed");

    err = verify_role_fetch(&creds, &REPO_IMAGE, root_signed, "timestamp",
                            REPO_IMAGE.vt_ts, now, &ts_v, &ts_env, NULL, NULL);
    if (err != ESP_OK) goto cleanup;

    err = verify_role_fetch(&creds, &REPO_IMAGE, root_signed, "snapshot",
                            REPO_IMAGE.vt_snap, now, &snap_v, &snap_env,
                            &snap_raw, &snap_len);
    if (err != ESP_OK) goto cleanup;

    err = verify_role_fetch(&creds, &REPO_IMAGE, root_signed, "targets",
                            REPO_IMAGE.vt_tgt, now, &tgt_v, &tgt_env,
                            &tgt_raw, &tgt_len);
    if (err != ESP_OK) goto cleanup;

    /* Meta-hash chain over the raw served bytes. */
    cJSON *ts_signed   = cJSON_GetObjectItemCaseSensitive(ts_env, "signed");
    cJSON *snap_signed = cJSON_GetObjectItemCaseSensitive(snap_env, "signed");

    int rc = akt_verify_meta_link(ts_signed, "snapshot.json",
                                  (const uint8_t *)snap_raw, snap_len, snap_v);
    if (rc != AKT_OK) {
        ESP_LOGE(TAG, "Image chain: timestamp->snapshot meta-hash FAIL — %s",
                 akt_err_name(rc));
        err = map_akt_err(rc);
        goto cleanup;
    }
    rc = akt_verify_meta_link(snap_signed, "targets.json",
                              (const uint8_t *)tgt_raw, tgt_len, tgt_v);
    if (rc != AKT_OK) {
        ESP_LOGE(TAG, "Image chain: snapshot->targets meta-hash FAIL — %s",
                 akt_err_name(rc));
        err = map_akt_err(rc);
        goto cleanup;
    }
    ESP_LOGW(TAG, "Image repo VERIFIED: roles ok (root=v%ld ts=v%ld snap=v%ld "
                  "targets=v%ld) + meta-hash chain ts->snap->targets over raw "
                  "served bytes PASS", (long)root_v, (long)ts_v, (long)snap_v,
             (long)tgt_v);

    if (out_targets_env) { *out_targets_env = tgt_env; tgt_env = NULL; }

cleanup:
    cJSON_Delete(root_env);
    cJSON_Delete(ts_env);
    cJSON_Delete(snap_env);
    cJSON_Delete(tgt_env);
    free(snap_raw);
    free(tgt_raw);
    aktualino_store_free_creds(&creds);
    return err;
}

esp_err_t aktualino_core_crosscheck_target(const aktualino_poll_result_t *res,
                                           int64_t now)
{
    if (!res || !res->target_assigned) return ESP_ERR_INVALID_ARG;

    cJSON *img_tgt_env = NULL;
    esp_err_t err = aktualino_core_verify_image_repo(now, &img_tgt_env);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "CROSS-REPO REFUSE: Image repo did not verify (%s) — "
                      "refusing to install %s", esp_err_to_name(err),
                 res->target_path);
        return err;
    }
    cJSON *img_tgt_signed = cJSON_GetObjectItemCaseSensitive(img_tgt_env, "signed");

    akt_target_t dir;
    memset(&dir, 0, sizeof(dir));
    snprintf(dir.filepath, sizeof(dir.filepath), "%s", res->target_path);
    memcpy(dir.sha256, res->target_sha256, 32);
    dir.length = res->target_length;

    int rc = akt_image_target_matches(img_tgt_signed, &dir);
    cJSON_Delete(img_tgt_env);

    if (rc == AKT_OK) {
        ESP_LOGW(TAG, "CROSS-REPO MATCH PASS: %s (sha256=%s len=%zu) is signed by "
                      "BOTH the Director and the Image repo — install allowed",
                 res->target_path, res->target_sha256_hex, res->target_length);
        return ESP_OK;
    }
    if (rc == AKT_ERR_NO_TARGET) {
        ESP_LOGE(TAG, "CROSS-REPO REFUSE (ATTACK): Director assigned %s but the "
                      "Image repo does NOT sign it — refusing install",
                 res->target_path);
    } else {
        ESP_LOGE(TAG, "CROSS-REPO REFUSE (ATTACK): %s is signed by both repos with "
                      "DIFFERENT sha256/length — refusing install", res->target_path);
    }
    return map_akt_err(rc);
}

/* ------------------------------------------------------------------ *
 * Phase 3 — download + install
 * ------------------------------------------------------------------ */

esp_err_t aktualino_core_target_is_new(const aktualino_poll_result_t *res,
                                       bool *is_new)
{
    if (is_new) *is_new = false;
    if (!res || !is_new) return ESP_ERR_INVALID_ARG;
    if (!res->target_assigned) return ESP_OK;

    esp_err_t err = aktualino_store_init();
    if (err != ESP_OK) return err;

    uint8_t run_sha[32];
    bool present = false;
    err = aktualino_store_get_running_image(NULL, 0, run_sha, NULL, &present);
    if (err != ESP_OK) return err;

    /* No recorded running image => any assigned target is new. Otherwise compare
     * the Director target hash to what is actually installed. */
    *is_new = !present || (memcmp(run_sha, res->target_sha256, 32) != 0);
    return ESP_OK;
}

/* Streaming sink: fold each downloaded chunk into the open OTA slot. */
static esp_err_t ota_sink_cb(const void *data, size_t len, void *user)
{
    return aktualino_ota_write((aktualino_ota_ctx_t *)user, data, len);
}

esp_err_t aktualino_core_download_and_install(const aktualino_poll_result_t *res,
                                              int64_t now)
{
    if (!res || !res->target_assigned) return ESP_ERR_INVALID_ARG;

    /*
     * THE UPTANE TWO-REPO GATE (SPEC §7, §15). Before touching flash, REQUIRE
     * that the Image repo independently signs the identical target the Director
     * assigned. This is the hard, structural guarantee: there is no path from a
     * Director assignment to an OTA write without the Image repo agreeing on
     * {filepath, sha256, length}. A Director-only or hash-mismatched target is
     * refused here (the caller reports the failure/attack).
     */
    esp_err_t err = aktualino_core_crosscheck_target(res, now);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "install ABORTED: cross-repo verification refused %s — "
                      "staying on current image", res->target_path);
        return err;
    }

    err = aktualino_store_init();
    if (err != ESP_OK) return err;

    aktualino_creds_t creds;
    err = aktualino_store_load_creds(&creds);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "install: load_creds failed: %s", esp_err_to_name(err));
        return err;
    }

    char url[400];
    snprintf(url, sizeof(url), "%s/repo/targets/%s",
             creds.gateway_url, res->target_path);
    ESP_LOGW(TAG, "DOWNLOAD: GET %s (expect len=%zu sha256=%s)",
             url, res->target_length, res->target_sha256_hex);

    /* Open the inactive slot; pass the expected length so the driver erases
     * precisely (SPEC §7.6). */
    aktualino_ota_ctx_t ota;
    err = aktualino_ota_begin(&ota, res->target_length);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "install: ota_begin failed: %s", esp_err_to_name(err));
        aktualino_store_free_creds(&creds);
        return err;
    }

    aktualino_net_get_cfg_t cfg = {
        .url = url,
        .cacert_pem = creds.cacert_pem,
        .client_cert_pem = creds.client_cert_pem,
        .client_key_pem = creds.client_key_pem,
        .timeout_ms = 60000,
    };
    int status = 0;
    size_t got = 0;
    err = aktualino_net_get_stream(&cfg, ota_sink_cb, &ota, &status, &got);
    if (err != ESP_OK || status != 200) {
        ESP_LOGE(TAG, "install: download failed (err=%s http=%d after %zu bytes)",
                 esp_err_to_name(err), status, got);
        aktualino_ota_abort(&ota);
        aktualino_store_free_creds(&creds);
        return (err != ESP_OK) ? err : ESP_FAIL;
    }

    /* Finalize flash + get the SHA-256 of exactly the bytes written. */
    uint8_t digest[32];
    err = aktualino_ota_end(&ota, digest);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "install: ota_end failed: %s (staying on current slot)",
                 esp_err_to_name(err));
        aktualino_store_free_creds(&creds);
        return err;
    }

    /* SPEC §7.5: verify length AND sha256 against the Director target. */
    if (got != res->target_length) {
        ESP_LOGE(TAG, "install: LENGTH MISMATCH — got %zu, expected %zu; abort",
                 got, res->target_length);
        aktualino_store_free_creds(&creds);
        return ESP_ERR_INVALID_SIZE;
    }
    if (memcmp(digest, res->target_sha256, 32) != 0) {
        char got_hex[65];
        akt_hex_encode(digest, 32, got_hex, sizeof(got_hex));
        ESP_LOGE(TAG, "install: SHA-256 MISMATCH — got %s, expected %s; abort",
                 got_hex, res->target_sha256_hex);
        aktualino_store_free_creds(&creds);
        return ESP_ERR_INVALID_CRC;
    }
    ESP_LOGW(TAG, "install: VERIFIED sha256 + length OK (%zu bytes)", got);

    /* Stage the pending record BEFORE flipping the boot slot, so the freshly
     * booted image knows what it installed and which assignment to report. */
    err = aktualino_store_set_pending_update(res->target_path, res->target_sha256,
                                             (uint32_t)res->target_length,
                                             res->correlation_id);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "install: could not stage pending update: %s",
                 esp_err_to_name(err));
        aktualino_store_free_creds(&creds);
        return err;
    }

    err = aktualino_ota_set_boot(&ota);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "install: set_boot failed: %s", esp_err_to_name(err));
        aktualino_store_clear_pending_update();
    } else {
        ESP_LOGW(TAG, "install: boot slot set — reboot to activate %s",
                 res->target_path);
    }
    aktualino_store_free_creds(&creds);
    return err;
}
