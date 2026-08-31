/*
 * Phase-3 host tests: the device-side pieces of the full cloud update loop.
 *   1. akt_select_target against the OTA-Connect Director targets shape
 *      (per-target custom.ecuIdentifiers.<serial>.hardwareId) + the top-level
 *      signed.custom.correlationId extraction (akt_targets_correlation_id).
 *   2. akt_build_manifest_report: a V3 manifest carrying an installation_report
 *      whose report.correlation_id + result.success let the Director mark the
 *      matching assignment completed — both signatures round-trip through
 *      akt_verify over canonical(signed).
 *
 * The target JSON below matches the shape the Director emits (signed.custom.
 * correlationId + custom.ecuIdentifiers). Values are synthetic.
 */
#include "akt_uptane.h"
#include "akt_crypto.h"
#include "cJSON.h"
#include "test_util.h"
#include <string.h>
#include <stdlib.h>

/* A device targets `signed` object in the Director's assignment shape
 * (correlationId + ecuIdentifiers.<serial>.hardwareId). Synthetic values. */
static const char *DIRECTOR_TARGETS_SIGNED =
"{\"_type\":\"Targets\","
 "\"custom\":{\"correlationId\":\"urn:here-ota:mtu:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\"},"
 "\"expires\":\"2026-10-01T03:56:53Z\","
 "\"targets\":{\"aktualino-esp32-0.2.0\":{"
    "\"custom\":{\"ecuIdentifiers\":{\"aktualinoespsynthecuserialaaaa\":{\"hardwareId\":\"aktualino-esp32\"}},"
              "\"uri\":null,\"userDefinedCustom\":null},"
    "\"hashes\":{\"sha256\":\"f0a52ba87756aa5d720231bc92c593714b02bcc8040b23bf5fcb56bef07e4f27\"},"
    "\"length\":1189488}},"
 "\"version\":2}";

/* Verify one signed envelope (signatures[]+signed) under pubkey `pk`. */
static bool verify_envelope(const cJSON *env, const uint8_t pk[32])
{
    const cJSON *signed_obj = cJSON_GetObjectItemCaseSensitive(env, "signed");
    const cJSON *sigs = cJSON_GetObjectItemCaseSensitive(env, "signatures");
    if (!cJSON_IsObject(signed_obj) || !cJSON_IsArray(sigs)) return false;
    const cJSON *s0 = cJSON_GetArrayItem(sigs, 0);
    const cJSON *method = cJSON_GetObjectItemCaseSensitive(s0, "method");
    const cJSON *sig_b64 = cJSON_GetObjectItemCaseSensitive(s0, "sig");
    if (!cJSON_IsString(method) || !cJSON_IsString(sig_b64)) return false;
    size_t canon_len = 0;
    char *canon = akt_canonical_json(signed_obj, &canon_len);
    if (!canon) return false;
    uint8_t sig[64]; size_t sig_len = 0;
    bool ok = false;
    if (akt_base64_decode(sig_b64->valuestring, sig, sizeof(sig), &sig_len) == 0 &&
        sig_len == 64)
        ok = akt_verify(method->valuestring, pk, 32, canon, canon_len, sig, sig_len);
    free(canon);
    return ok;
}

int main(void)
{
    /* ---- 1. target selection + correlation id (live Director shape) ---- */
    cJSON *ts = cJSON_Parse(DIRECTOR_TARGETS_SIGNED);
    CHECK(ts != NULL);

    akt_target_t t;
    CHECK_MSG(akt_select_target(ts, "aktualino-esp32", &t) == AKT_OK,
              "select by custom.ecuIdentifiers.<serial>.hardwareId");
    CHECK_STREQ(t.filepath, "aktualino-esp32-0.2.0");
    CHECK(t.length == 1189488);
    {
        char sha_hex[65];
        akt_hex_encode(t.sha256, 32, sha_hex, sizeof(sha_hex));
        CHECK_STREQ(sha_hex,
            "f0a52ba87756aa5d720231bc92c593714b02bcc8040b23bf5fcb56bef07e4f27");
    }
    /* a hw id not present must not match */
    {
        akt_target_t t2;
        CHECK(akt_select_target(ts, "some-other-hw", &t2) == AKT_ERR_NO_TARGET);
    }
    /* correlation id from signed.custom.correlationId */
    {
        char cid[128];
        CHECK(akt_targets_correlation_id(ts, cid, sizeof(cid)) == AKT_OK);
        CHECK_STREQ(cid, "urn:here-ota:mtu:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    }
    cJSON_Delete(ts);

    /* an empty-custom targets object yields no correlation id */
    {
        cJSON *empty = cJSON_Parse("{\"targets\":{}}");
        char cid[128];
        CHECK(akt_targets_correlation_id(empty, cid, sizeof(cid)) == AKT_ERR_NO_TARGET);
        cJSON_Delete(empty);
    }

    /* ---- 2. manifest with installation_report ---- */
    uint8_t pk[32], sk[64];
    CHECK(akt_keygen_ed25519(pk, sk) == 0);

    akt_target_t installed;
    memset(&installed, 0, sizeof(installed));
    strcpy(installed.filepath, "aktualino-esp32-0.2.0");
    installed.length = 1189488;
    for (int i = 0; i < 32; i++) installed.sha256[i] = (uint8_t)(i + 3);

    const char *CID = "urn:here-ota:mtu:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    size_t len = 0;
    char *json = akt_build_manifest_report("ecuserial01", &installed, "",
                                           CID, true, pk, sk, &len);
    CHECK(json != NULL);
    if (!json) { TEST_SUMMARY("phase3"); }
    CHECK(len == strlen(json));

    cJSON *outer = cJSON_Parse(json);
    CHECK(outer != NULL);
    CHECK_MSG(verify_envelope(outer, pk), "outer sig verify");

    cJSON *osigned = cJSON_GetObjectItemCaseSensitive(outer, "signed");
    cJSON *evm = cJSON_GetObjectItemCaseSensitive(osigned, "ecu_version_manifests");
    cJSON *inner = cJSON_GetObjectItemCaseSensitive(evm, "ecuserial01");
    CHECK_MSG(verify_envelope(inner, pk), "inner sig verify");

    /* installation_report shape (SPEC Appendix A / director v3 fixture) */
    cJSON *ir = cJSON_GetObjectItemCaseSensitive(osigned, "installation_report");
    CHECK_MSG(cJSON_IsObject(ir), "installation_report present (not null)");
    cJSON *ct = cJSON_GetObjectItemCaseSensitive(ir, "content_type");
    CHECK(cJSON_IsString(ct) &&
          strcmp(ct->valuestring,
                 "application/vnd.com.here.otac.installationReport.v1") == 0);
    cJSON *report = cJSON_GetObjectItemCaseSensitive(ir, "report");
    cJSON *rcid = cJSON_GetObjectItemCaseSensitive(report, "correlation_id");
    CHECK(cJSON_IsString(rcid));
    CHECK_STREQ(rcid->valuestring, CID);
    cJSON *result = cJSON_GetObjectItemCaseSensitive(report, "result");
    cJSON *succ = cJSON_GetObjectItemCaseSensitive(result, "success");
    CHECK(cJSON_IsBool(succ) && cJSON_IsTrue(succ));
    cJSON *items = cJSON_GetObjectItemCaseSensitive(report, "items");
    CHECK(cJSON_IsArray(items) && cJSON_GetArraySize(items) == 1);
    cJSON *item0 = cJSON_GetArrayItem(items, 0);
    cJSON *iecu = cJSON_GetObjectItemCaseSensitive(item0, "ecu");
    CHECK(cJSON_IsString(iecu) && strcmp(iecu->valuestring, "ecuserial01") == 0);

    /* installed_image must equal the target (director assignmentExists match) */
    cJSON *isigned = cJSON_GetObjectItemCaseSensitive(inner, "signed");
    cJSON *img = cJSON_GetObjectItemCaseSensitive(isigned, "installed_image");
    cJSON *fp = cJSON_GetObjectItemCaseSensitive(img, "filepath");
    CHECK_STREQ(fp->valuestring, "aktualino-esp32-0.2.0");

    cJSON_Delete(outer);
    free(json);

    /* ---- 3. a FAILURE report flips result.success ---- */
    {
        size_t l2 = 0;
        char *jf = akt_build_manifest_report("ecuserial01", &installed, "",
                                             CID, false, pk, sk, &l2);
        CHECK(jf != NULL);
        cJSON *o2 = cJSON_Parse(jf);
        cJSON *s2 = cJSON_GetObjectItemCaseSensitive(o2, "signed");
        cJSON *ir2 = cJSON_GetObjectItemCaseSensitive(s2, "installation_report");
        cJSON *rep2 = cJSON_GetObjectItemCaseSensitive(ir2, "report");
        cJSON *res2 = cJSON_GetObjectItemCaseSensitive(rep2, "result");
        cJSON *su2 = cJSON_GetObjectItemCaseSensitive(res2, "success");
        CHECK_MSG(cJSON_IsFalse(su2), "failure report result.success == false");
        cJSON_Delete(o2);
        free(jf);
    }

    TEST_SUMMARY("phase3");
}
