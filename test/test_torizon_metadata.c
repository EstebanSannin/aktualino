/*
 * Torizon Cloud RSA path — run the portable Uptane verification core against
 * synthetic, Torizon-Cloud-shaped metadata (RSASSA-PSS-SHA256 / RSA-2048).
 *
 * Torizon Cloud signs every role with rsassa-pss-sha256 over an RSA-2048 key.
 * This test proves our canonical-JSON + RSA verify path agrees with Torizon-
 * shaped metadata:
 *
 *   - Both trust-anchor roots (Director, Image) verify their OWN signature
 *     (self-signed root) against their embedded RSA root key.
 *   - Every Director role (timestamp/snapshot/targets) verifies against the
 *     Director RSA root keys; every Image role verifies against the Image RSA
 *     root keys. Because the signature is over canonical(signed), "verifies" IS
 *     byte-exact canonical-JSON agreement — enforced by the crypto itself.
 *   - The Image-repo meta-hash chain (timestamp->snapshot->{root,targets}) holds
 *     over the RAW served bytes (length + sha256 + version).
 *   - Expiry and tamper gates fire on RSA metadata.
 *
 * The fixtures are synthetic (throwaway RSA keys, no real account data) generated
 * by test/fixtures/make_synthetic_torizon.py; the header is emitted at build time
 * by gen_torizon.py.
 */
#include "akt_uptane.h"
#include "akt_crypto.h"
#include "cJSON.h"
#include "test_util.h"
#include "synthetic_torizon_metadata.h"
#include <string.h>
#include <stdlib.h>

/* Detach and return the "signed" object of an envelope string. */
static cJSON *signed_of(const char *env)
{
    cJSON *e = cJSON_Parse(env);
    if (!e) return NULL;
    cJSON *s = cJSON_DetachItemFromObjectCaseSensitive(e, "signed");
    cJSON_Delete(e);
    return s;
}

int main(void)
{
    /* A time inside every validity window: 2026-09-01T00:00:00Z. */
    const time_t now = 1756684800;
    /* A time past the Image-role expiry (2028) for the expiry gate: 2030-01-01. */
    const time_t y2030 = 1893456000;

    /* ---- 1. Anchor roots self-verify (RSA self-signed root) ---------- */
    cJSON *dir_root_signed = signed_of(TZ_ANCHOR_DIRECTOR_ROOT);
    cJSON *img_root_signed = signed_of(TZ_ANCHOR_IMAGE_ROOT);
    CHECK_MSG(dir_root_signed != NULL, "parse Director anchor root");
    CHECK_MSG(img_root_signed != NULL, "parse Image anchor root");

    {
        cJSON *env = cJSON_Parse(TZ_ANCHOR_DIRECTOR_ROOT);
        int rc = akt_verify_role(dir_root_signed, "root", env, now, 0);
        CHECK_MSG(rc == AKT_OK, "Director root self-sig (RSA) must verify (rc=%d)", rc);
        cJSON_Delete(env);
    }
    {
        cJSON *env = cJSON_Parse(TZ_ANCHOR_IMAGE_ROOT);
        int rc = akt_verify_role(img_root_signed, "root", env, now, 0);
        CHECK_MSG(rc == AKT_OK, "Image root self-sig (RSA) must verify (rc=%d)", rc);
        cJSON_Delete(env);
    }

    /* ---- 2. Live Director roles verify against the Director RSA root -- */
    struct { const char *role; const char *env; } dir_roles[] = {
        {"root",      TZ_DIR_ROOT},
        {"timestamp", TZ_DIR_TIMESTAMP},
        {"snapshot",  TZ_DIR_SNAPSHOT},
        {"targets",   TZ_DIR_TARGETS},
    };
    for (unsigned i = 0; i < 4; i++) {
        cJSON *env = cJSON_Parse(dir_roles[i].env);
        int rc = akt_verify_role(dir_root_signed, dir_roles[i].role, env, now, 0);
        CHECK_MSG(rc == AKT_OK,
                  "live Director %s must verify against Torizon RSA root (rc=%d)",
                  dir_roles[i].role, rc);
        cJSON_Delete(env);
    }

    /* ---- 3. Live Image roles verify against the Image RSA root -------- */
    struct { const char *role; const char *env; } img_roles[] = {
        {"root",      TZ_IMG_ROOT},
        {"timestamp", TZ_IMG_TIMESTAMP},
        {"snapshot",  TZ_IMG_SNAPSHOT},
        {"targets",   TZ_IMG_TARGETS},
    };
    for (unsigned i = 0; i < 4; i++) {
        cJSON *env = cJSON_Parse(img_roles[i].env);
        int rc = akt_verify_role(img_root_signed, img_roles[i].role, env, now, 0);
        CHECK_MSG(rc == AKT_OK,
                  "live Image %s must verify against Torizon RSA root (rc=%d)",
                  img_roles[i].role, rc);
        cJSON_Delete(env);
    }

    /* ---- 4. Image-repo meta-hash chain over RAW served bytes ---------- */
    /* timestamp.meta["snapshot.json"] pins the Image snapshot (v4). */
    {
        cJSON *ts_signed = signed_of(TZ_IMG_TIMESTAMP);
        int rc = akt_verify_meta_link(ts_signed, "snapshot.json",
                                      (const uint8_t *)TZ_IMG_SNAPSHOT,
                                      sizeof(TZ_IMG_SNAPSHOT) - 1, 4);
        CHECK_MSG(rc == AKT_OK, "Image timestamp->snapshot hash chain (rc=%d)", rc);
        cJSON_Delete(ts_signed);
    }
    /* snapshot.meta["root.json"] and ["targets.json"] pin those files. */
    {
        cJSON *sn_signed = signed_of(TZ_IMG_SNAPSHOT);
        int rc_r = akt_verify_meta_link(sn_signed, "root.json",
                                        (const uint8_t *)TZ_IMG_ROOT,
                                        sizeof(TZ_IMG_ROOT) - 1, 2);
        CHECK_MSG(rc_r == AKT_OK, "Image snapshot->root hash chain (rc=%d)", rc_r);
        int rc_t = akt_verify_meta_link(sn_signed, "targets.json",
                                        (const uint8_t *)TZ_IMG_TARGETS,
                                        sizeof(TZ_IMG_TARGETS) - 1, 3);
        CHECK_MSG(rc_t == AKT_OK, "Image snapshot->targets hash chain (rc=%d)", rc_t);

        /* A one-byte length lie must be caught. */
        int rc_bad = akt_verify_meta_link(sn_signed, "targets.json",
                                          (const uint8_t *)TZ_IMG_TARGETS,
                                          sizeof(TZ_IMG_TARGETS) - 2, 3);
        CHECK_MSG(rc_bad == AKT_ERR_CROSSREPO, "truncated Image targets must fail chain (rc=%d)", rc_bad);
        cJSON_Delete(sn_signed);
    }

    /* ---- 5. Expiry gate fires on real RSA metadata ------------------- */
    {
        cJSON *env = cJSON_Parse(TZ_IMG_TIMESTAMP);
        int rc = akt_verify_role(img_root_signed, "timestamp", env, y2030, 0);
        CHECK_MSG(rc == AKT_ERR_EXPIRED, "live Image timestamp EXPIRED in 2030 (rc=%d)", rc);
        cJSON_Delete(env);
    }

    /* ---- 6. Tampered RSA signature must fail threshold --------------- */
    {
        /* Flip one base64 char of the Director targets signature. */
        char *buf = strdup(TZ_DIR_TARGETS);
        char *sig = strstr(buf, "\"sig\":\"");
        CHECK_MSG(sig != NULL, "locate sig field");
        sig += 7;
        sig[0] = (sig[0] == 'A') ? 'B' : 'A';   /* corrupt first sig byte */
        cJSON *env = cJSON_Parse(buf);
        int rc = akt_verify_role(dir_root_signed, "targets", env, now, 0);
        CHECK_MSG(rc == AKT_ERR_THRESHOLD, "tampered RSA sig must fail THRESHOLD (rc=%d)", rc);
        cJSON_Delete(env);
        free(buf);
    }

    /* ---- 7. Anti-rollback: min_version above the live version -------- */
    {
        cJSON *env = cJSON_Parse(TZ_IMG_TARGETS);
        int rc = akt_verify_role(img_root_signed, "targets", env, now, 100000);
        CHECK_MSG(rc == AKT_ERR_ROLLBACK, "min_version gate must ROLLBACK (rc=%d)", rc);
        cJSON_Delete(env);
    }

    cJSON_Delete(dir_root_signed);
    cJSON_Delete(img_root_signed);
    TEST_SUMMARY("test_torizon_metadata");
}
