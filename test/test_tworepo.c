/*
 * test_tworepo.c — Phase 4a: Image-repo meta-hash chain + cross-repo target
 * matching (the Uptane two-repo guarantee).
 *
 * Two proofs:
 *   1. The meta-hash chain (timestamp -> snapshot -> targets/root) verifies over
 *      the RAW SERVED BYTES of each envelope — both on a controlled synthetic
 *      fixture (so the raw-bytes semantic is explicit) AND against the synthetic
 *      Torizon-shaped Image-repo metadata (RSASSA-PSS-SHA256 / RSA-2048), where
 *      every role ALSO signature-verifies against the image-repo root keys (that
 *      is the byte-exact canonical-JSON agreement, enforced by the crypto). A
 *      tampered byte / length / version is refused.
 *   2. Cross-repo target matching: a Director-assigned target installs ONLY when
 *      the identical {filepath, sha256, length} is signed in the Image-repo
 *      targets.json. A Director-only target and a hash/length mismatch REFUSE.
 *
 * The image-repo hash rule (as the OTA-Connect reposerver stores signed roles):
 *   parent.meta[child].hashes.sha256 == SHA256( raw served bytes of child ),
 * where the served bytes ARE the whole {signatures,signed} envelope. The device
 * hashes exactly the bytes on the wire.
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

/* Build a referrer `signed` with meta[key] = { hashes.sha256, length, version }
 * computed over the RAW bytes `file`/`flen` — mirrors what the reposerver does. */
static cJSON *make_referrer(const char *key, const uint8_t *file, size_t flen,
                            long version)
{
    uint8_t d[32]; char hex[65];
    akt_sha256(file, flen, d);
    akt_hex_encode(d, 32, hex, sizeof(hex));
    cJSON *sig = cJSON_CreateObject();
    cJSON *meta = cJSON_CreateObject();
    cJSON *entry = cJSON_CreateObject();
    cJSON *hashes = cJSON_CreateObject();
    cJSON_AddStringToObject(hashes, "sha256", hex);
    cJSON_AddItemToObject(entry, "hashes", hashes);
    cJSON_AddNumberToObject(entry, "length", (double)flen);
    cJSON_AddNumberToObject(entry, "version", (double)version);
    cJSON_AddItemToObject(meta, key, entry);
    cJSON_AddItemToObject(sig, "meta", meta);
    return sig;
}

/* Fill an akt_target_t from hex sha + length + filepath. */
static void make_target(akt_target_t *t, const char *fp, const char *sha_hex,
                        size_t len)
{
    memset(t, 0, sizeof(*t));
    snprintf(t->filepath, sizeof(t->filepath), "%s", fp);
    size_t n = 0;
    akt_hex_decode(sha_hex, t->sha256, 32, &n);
    t->length = len;
}

int main(void)
{
    /* ---- 1a. controlled synthetic chain over raw bytes ---- */
    {
        const uint8_t blob[] = "raw-served-snapshot-envelope-bytes-\x01\x02\x03";
        size_t blen = sizeof(blob) - 1;
        cJSON *ref = make_referrer("snapshot.json", blob, blen, 7);

        CHECK_MSG(akt_verify_meta_link(ref, "snapshot.json", blob, blen, 7) == AKT_OK,
                  "synthetic meta-link over raw bytes must PASS");
        /* tampered byte -> CROSSREPO */
        uint8_t bad[64]; memcpy(bad, blob, blen); bad[0] ^= 0x40;
        CHECK_MSG(akt_verify_meta_link(ref, "snapshot.json", bad, blen, 7) == AKT_ERR_CROSSREPO,
                  "tampered raw bytes must be CROSSREPO");
        /* wrong length -> CROSSREPO */
        CHECK_MSG(akt_verify_meta_link(ref, "snapshot.json", blob, blen - 1, 7) == AKT_ERR_CROSSREPO,
                  "wrong length must be CROSSREPO");
        /* wrong version -> CROSSREPO */
        CHECK_MSG(akt_verify_meta_link(ref, "snapshot.json", blob, blen, 8) == AKT_ERR_CROSSREPO,
                  "wrong version must be CROSSREPO");
        /* missing key -> PARSE */
        CHECK_MSG(akt_verify_meta_link(ref, "targets.json", blob, blen, 7) == AKT_ERR_PARSE,
                  "absent meta key must be PARSE");
        cJSON_Delete(ref);
    }

    /* ---- 1b. image-repo: signatures verify against the image root ---- */
    cJSON *img_root_signed = signed_of(TZ_IMG_ROOT);
    CHECK_MSG(img_root_signed != NULL, "parse image root signed");
    const time_t now = 1756771200; /* 2026-09-02, inside every image window */
    struct { const char *role; const char *env; } roles[] = {
        {"root",      TZ_IMG_ROOT},
        {"timestamp", TZ_IMG_TIMESTAMP},
        {"snapshot",  TZ_IMG_SNAPSHOT},
        {"targets",   TZ_IMG_TARGETS},
    };
    for (unsigned i = 0; i < 4; i++) {
        cJSON *env = cJSON_Parse(roles[i].env);
        int rc = akt_verify_role(img_root_signed, roles[i].role, env, now, 0);
        CHECK_MSG(rc == AKT_OK,
                  "image %s must verify against image root keys (rc=%d)",
                  roles[i].role, rc);
        cJSON_Delete(env);
    }

    /* ---- 1c. image-repo meta-hash chain over the raw served bytes ---- */
    {
        cJSON *ts_signed   = signed_of(TZ_IMG_TIMESTAMP);
        cJSON *snap_signed = signed_of(TZ_IMG_SNAPSHOT);
        const uint8_t *snap_b = (const uint8_t *)TZ_IMG_SNAPSHOT;
        size_t snap_n = sizeof(TZ_IMG_SNAPSHOT) - 1;
        const uint8_t *tgt_b  = (const uint8_t *)TZ_IMG_TARGETS;
        size_t tgt_n  = sizeof(TZ_IMG_TARGETS) - 1;
        const uint8_t *root_b = (const uint8_t *)TZ_IMG_ROOT;
        size_t root_n = sizeof(TZ_IMG_ROOT) - 1;

        /* timestamp.meta[snapshot.json] pins the snapshot bytes (v4). */
        CHECK_MSG(akt_verify_meta_link(ts_signed, "snapshot.json", snap_b, snap_n, 4) == AKT_OK,
                  "timestamp -> snapshot chain must PASS over raw bytes");
        /* snapshot.meta[targets.json] pins the targets bytes (v3). */
        CHECK_MSG(akt_verify_meta_link(snap_signed, "targets.json", tgt_b, tgt_n, 3) == AKT_OK,
                  "snapshot -> targets chain must PASS over raw bytes");
        /* snapshot.meta[root.json] pins the root bytes (v2). */
        CHECK_MSG(akt_verify_meta_link(snap_signed, "root.json", root_b, root_n, 2) == AKT_OK,
                  "snapshot -> root chain must PASS over raw bytes");

        /* NEGATIVE: feed the snapshot bytes where the targets bytes are expected. */
        CHECK_MSG(akt_verify_meta_link(snap_signed, "targets.json", snap_b, snap_n, 3) == AKT_ERR_CROSSREPO,
                  "wrong file for a meta entry must be CROSSREPO");
        /* NEGATIVE: truncate the targets bytes by one. */
        CHECK_MSG(akt_verify_meta_link(snap_signed, "targets.json", tgt_b, tgt_n - 1, 3) == AKT_ERR_CROSSREPO,
                  "truncated targets must be CROSSREPO");

        cJSON_Delete(ts_signed);
        cJSON_Delete(snap_signed);
    }

    /* ---- 2. cross-repo target matching against the image targets ---- */
    {
        cJSON *img_tgts = signed_of(TZ_IMG_TARGETS);
        CHECK_MSG(img_tgts != NULL, "parse image targets signed");

        /* The synthetic target both repos sign. */
        const char *FP  = TZ_TARGET_FILEPATH;
        const char *SHA = TZ_TARGET_SHA256;
        const size_t LEN = TZ_TARGET_LENGTH;

        akt_target_t dir;
        make_target(&dir, FP, SHA, LEN);
        CHECK_MSG(akt_image_target_matches(img_tgts, &dir) == AKT_OK,
                  "both repos AGREE on the target -> install allowed");

        /* REFUSE: Director references a target the image repo does not sign. */
        akt_target_t only;
        make_target(&only, "aktualino-esp32-9.9.9-evil", SHA, LEN);
        CHECK_MSG(akt_image_target_matches(img_tgts, &only) == AKT_ERR_NO_TARGET,
                  "Director-only target (absent in image repo) must REFUSE (NO_TARGET)");

        /* REFUSE: same filepath, tampered sha256. */
        akt_target_t badsha;
        make_target(&badsha, FP,
                    "0000000000000000000000000000000000000000000000000000000000000000", LEN);
        CHECK_MSG(akt_image_target_matches(img_tgts, &badsha) == AKT_ERR_CROSSREPO,
                  "hash mismatch across repos must REFUSE (CROSSREPO)");

        /* REFUSE: same filepath + sha, wrong length. */
        akt_target_t badlen;
        make_target(&badlen, FP, SHA, LEN + 1);
        CHECK_MSG(akt_image_target_matches(img_tgts, &badlen) == AKT_ERR_CROSSREPO,
                  "length mismatch across repos must REFUSE (CROSSREPO)");

        cJSON_Delete(img_tgts);
    }

    cJSON_Delete(img_root_signed);
    TEST_SUMMARY("tworepo");
}
