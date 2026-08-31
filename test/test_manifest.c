/* T1.4 V3 device manifest: build, then verify BOTH signatures round-trip
 * through akt_verify over canonical(signed); assert the Appendix A shape. */
#include "akt_uptane.h"
#include "akt_crypto.h"
#include "cJSON.h"
#include "test_util.h"
#include <string.h>
#include <stdlib.h>

/* Verify one signed envelope (signatures[]+signed) against pubkey `pk`. */
static bool verify_envelope(const cJSON *env, const uint8_t pk[32], const char *label)
{
    const cJSON *signed_obj = cJSON_GetObjectItemCaseSensitive(env, "signed");
    const cJSON *sigs = cJSON_GetObjectItemCaseSensitive(env, "signatures");
    if (!cJSON_IsObject(signed_obj) || !cJSON_IsArray(sigs)) {
        printf("  (%s) bad envelope shape\n", label); return false;
    }
    const cJSON *s0 = cJSON_GetArrayItem(sigs, 0);
    const cJSON *method = cJSON_GetObjectItemCaseSensitive(s0, "method");
    const cJSON *sig_b64 = cJSON_GetObjectItemCaseSensitive(s0, "sig");
    const cJSON *keyid = cJSON_GetObjectItemCaseSensitive(s0, "keyid");
    if (!cJSON_IsString(method) || !cJSON_IsString(sig_b64) || !cJSON_IsString(keyid))
        return false;

    /* keyid must match the derived Ed25519 keyid */
    char want_keyid[65];
    akt_keyid_ed25519(pk, want_keyid);
    if (strcmp(keyid->valuestring, want_keyid) != 0) {
        printf("  (%s) keyid mismatch\n", label); return false;
    }

    size_t canon_len = 0;
    char *canon = akt_canonical_json(signed_obj, &canon_len);
    if (!canon) return false;
    uint8_t sig[64]; size_t sig_len = 0;
    bool ok = false;
    if (akt_base64_decode(sig_b64->valuestring, sig, sizeof(sig), &sig_len) == 0 &&
        sig_len == 64) {
        ok = akt_verify(method->valuestring, pk, 32, canon, canon_len, sig, sig_len);
    }
    free(canon);
    return ok;
}

int main(void)
{
    uint8_t pk[32], sk[64];
    CHECK(akt_keygen_ed25519(pk, sk) == 0);

    akt_target_t installed;
    memset(&installed, 0, sizeof(installed));
    strcpy(installed.filepath, "aktualino/1.0.2/aktualino-app.bin");
    installed.length = 1048576;
    installed.version = 2;
    for (int i = 0; i < 32; i++) installed.sha256[i] = (uint8_t)(i * 7 + 1);

    size_t len = 0;
    char *json = akt_build_manifest("aktualino-esp32-01", &installed, "", pk, sk, &len);
    CHECK(json != NULL);
    if (!json) { TEST_SUMMARY("manifest"); }
    CHECK(len == strlen(json));

    cJSON *outer = cJSON_Parse(json);
    CHECK(outer != NULL);

    /* --- outer signature round-trip --- */
    CHECK_MSG(verify_envelope(outer, pk, "outer") == true, "outer sig verify");

    /* --- shape: outer.signed --- */
    cJSON *osigned = cJSON_GetObjectItemCaseSensitive(outer, "signed");
    cJSON *pes = cJSON_GetObjectItemCaseSensitive(osigned, "primary_ecu_serial");
    CHECK(cJSON_IsString(pes));
    CHECK_STREQ(pes->valuestring, "aktualino-esp32-01");
    cJSON *evm = cJSON_GetObjectItemCaseSensitive(osigned, "ecu_version_manifests");
    CHECK(cJSON_IsObject(evm));
    cJSON *ir = cJSON_GetObjectItemCaseSensitive(osigned, "installation_report");
    CHECK_MSG(cJSON_IsNull(ir), "installation_report must be null");

    /* --- inner SignedPayload[EcuManifest] --- */
    cJSON *inner = cJSON_GetObjectItemCaseSensitive(evm, "aktualino-esp32-01");
    CHECK(cJSON_IsObject(inner));
    CHECK_MSG(verify_envelope(inner, pk, "inner") == true, "inner sig verify");

    cJSON *isigned = cJSON_GetObjectItemCaseSensitive(inner, "signed");
    cJSON *img = cJSON_GetObjectItemCaseSensitive(isigned, "installed_image");
    cJSON *fp = cJSON_GetObjectItemCaseSensitive(img, "filepath");
    CHECK(cJSON_IsString(fp));
    CHECK_STREQ(fp->valuestring, "aktualino/1.0.2/aktualino-app.bin");
    cJSON *finfo = cJSON_GetObjectItemCaseSensitive(img, "fileinfo");
    cJSON *hashes = cJSON_GetObjectItemCaseSensitive(finfo, "hashes");
    cJSON *sha = cJSON_GetObjectItemCaseSensitive(hashes, "sha256");
    CHECK(cJSON_IsString(sha) && strlen(sha->valuestring) == 64);
    cJSON *length = cJSON_GetObjectItemCaseSensitive(finfo, "length");
    CHECK(cJSON_IsNumber(length) && (long)length->valuedouble == 1048576);
    cJSON *es = cJSON_GetObjectItemCaseSensitive(isigned, "ecu_serial");
    CHECK(cJSON_IsString(es) && strcmp(es->valuestring, "aktualino-esp32-01") == 0);
    cJSON *ad = cJSON_GetObjectItemCaseSensitive(isigned, "attacks_detected");
    CHECK(cJSON_IsString(ad) && strcmp(ad->valuestring, "") == 0);

    /* --- verify the embedded sha256 hex matches the installed hash --- */
    {
        char want[65];
        akt_hex_encode(installed.sha256, 32, want, sizeof(want));
        CHECK_STREQ(sha->valuestring, want);
    }

    /* --- negative: a wrong key must NOT verify --- */
    {
        uint8_t pk2[32], sk2[64];
        akt_keygen_ed25519(pk2, sk2);
        CHECK_MSG(verify_envelope(outer, pk2, "outer-wrongkey") == false,
                  "outer must not verify under a different key");
    }

    /* --- dual-ECU manifest: the Berry script secondary (spec §2/§3) --- */
    {
        akt_secondary_t sec;
        memset(&sec, 0, sizeof(sec));
        sec.ecu_serial = "aktualino-lua-01";
        sec.attacks_detected = "";
        strcpy(sec.installed.filepath, "aktualino-lua/1.4.0/blink.be");
        sec.installed.length = 320;
        sec.installed.version = 3;
        for (int i = 0; i < 32; i++) sec.installed.sha256[i] = (uint8_t)(i * 3 + 9);

        size_t len2 = 0;
        char *json2 = akt_build_manifest_ex("aktualino-esp32-01", &installed, "",
                                            NULL, true, &sec, pk, sk, &len2);
        CHECK(json2 != NULL);
        cJSON *outer2 = cJSON_Parse(json2);
        CHECK(outer2 != NULL);
        CHECK_MSG(verify_envelope(outer2, pk, "dual-outer") == true, "dual outer sig");

        cJSON *osigned2 = cJSON_GetObjectItemCaseSensitive(outer2, "signed");
        cJSON *evm2 = cJSON_GetObjectItemCaseSensitive(osigned2, "ecu_version_manifests");
        CHECK(cJSON_IsObject(evm2));

        /* both ECUs present; each nested manifest verifies under the SAME key */
        cJSON *m_prim = cJSON_GetObjectItemCaseSensitive(evm2, "aktualino-esp32-01");
        cJSON *m_sec  = cJSON_GetObjectItemCaseSensitive(evm2, "aktualino-lua-01");
        CHECK_MSG(cJSON_IsObject(m_prim), "primary ecu manifest present");
        CHECK_MSG(cJSON_IsObject(m_sec),  "secondary ecu manifest present");
        CHECK_MSG(verify_envelope(m_prim, pk, "dual-inner-primary") == true,
                  "primary inner sig");
        CHECK_MSG(verify_envelope(m_sec, pk, "dual-inner-secondary") == true,
                  "secondary inner sig (key reuse)");

        /* secondary installed_image shape */
        cJSON *s_signed = cJSON_GetObjectItemCaseSensitive(m_sec, "signed");
        cJSON *s_es = cJSON_GetObjectItemCaseSensitive(s_signed, "ecu_serial");
        CHECK(cJSON_IsString(s_es) && strcmp(s_es->valuestring, "aktualino-lua-01") == 0);
        cJSON *s_img = cJSON_GetObjectItemCaseSensitive(s_signed, "installed_image");
        cJSON *s_fp = cJSON_GetObjectItemCaseSensitive(s_img, "filepath");
        CHECK(cJSON_IsString(s_fp) &&
              strcmp(s_fp->valuestring, "aktualino-lua/1.4.0/blink.be") == 0);

        /* outer primary_ecu_serial is still the primary */
        cJSON *p2 = cJSON_GetObjectItemCaseSensitive(osigned2, "primary_ecu_serial");
        CHECK_STREQ(p2->valuestring, "aktualino-esp32-01");

        /* regression: the single-ECU manifest (evm) has NO secondary entry */
        CHECK_MSG(cJSON_GetObjectItemCaseSensitive(evm, "aktualino-lua-01") == NULL,
                  "single-ECU manifest has no secondary entry");

        cJSON_Delete(outer2);
        free(json2);
    }

    /* --- secondary-scoped installation_report drives completion (spec §14.7) --- */
    {
        akt_secondary_t sec;
        memset(&sec, 0, sizeof(sec));
        sec.ecu_serial = "aktualino-lua-01";
        sec.attacks_detected = "";
        strcpy(sec.installed.filepath, "aktualino-lua/1.4.0/blink.be");
        sec.installed.length = 320;
        for (int i = 0; i < 32; i++) sec.installed.sha256[i] = (uint8_t)(i * 3 + 9);
        sec.correlation_id = "corr-lua-abc123";   /* the secondary update's id */
        sec.success = true;

        size_t len3 = 0;
        char *json3 = akt_build_manifest_ex("aktualino-esp32-01", &installed, "",
                                            NULL, true, &sec, pk, sk, &len3);
        CHECK(json3 != NULL);
        cJSON *outer3 = cJSON_Parse(json3);
        CHECK(outer3 != NULL);

        cJSON *osigned3 = cJSON_GetObjectItemCaseSensitive(outer3, "signed");
        cJSON *ir3 = cJSON_GetObjectItemCaseSensitive(osigned3, "installation_report");
        CHECK_MSG(cJSON_IsObject(ir3), "installation_report present for the secondary");
        cJSON *rep = cJSON_GetObjectItemCaseSensitive(ir3, "report");
        cJSON *corr = cJSON_GetObjectItemCaseSensitive(rep, "correlation_id");
        CHECK(cJSON_IsString(corr));
        CHECK_STREQ(corr->valuestring, "corr-lua-abc123");
        /* report.items[0].ecu must be the SECONDARY ecu_serial, not the primary */
        cJSON *items = cJSON_GetObjectItemCaseSensitive(rep, "items");
        cJSON *item0 = cJSON_GetArrayItem(items, 0);
        cJSON *ecu = cJSON_GetObjectItemCaseSensitive(item0, "ecu");
        CHECK(cJSON_IsString(ecu));
        CHECK_STREQ(ecu->valuestring, "aktualino-lua-01");
        cJSON *rres = cJSON_GetObjectItemCaseSensitive(rep, "result");
        cJSON *rsucc = cJSON_GetObjectItemCaseSensitive(rres, "success");
        CHECK_MSG(cJSON_IsTrue(rsucc), "report.result.success is true");

        cJSON_Delete(outer3);
        free(json3);
    }

    cJSON_Delete(outer);
    free(json);
    TEST_SUMMARY("manifest");
}
