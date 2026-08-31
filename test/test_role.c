/* T1.3 role verification + Director target selection, driven by gen.py fixtures. */
#include "akt_uptane.h"
#include "akt_crypto.h"
#include "cJSON.h"
#include "test_util.h"
#include "generated_fixtures.h"
#include <string.h>
#include <stdlib.h>

static int verify_targets(const char *root, const char *env, long min_version)
{
    return akt_verify_role_bytes(root, strlen(root), "targets",
                                 env, strlen(env), FIXTURE_NOW, min_version);
}

int main(void)
{
    /* good -> PASS */
    CHECK_MSG(verify_targets(FIXTURE_ROOT_SIGNED,
                             FIXTURE_TARGETS_ENVELOPE_GOOD,
                             FIXTURE_TARGETS_VERSION) == AKT_OK,
              "good envelope should verify");

    /* tampered signature -> THRESHOLD (no valid sig) */
    CHECK_MSG(verify_targets(FIXTURE_ROOT_SIGNED,
                             FIXTURE_TARGETS_ENVELOPE_TAMPERED,
                             FIXTURE_TARGETS_VERSION) == AKT_ERR_THRESHOLD,
              "tampered sig should fail threshold");

    /* expired -> EXPIRED (sig valid, but past expiry) */
    CHECK_MSG(verify_targets(FIXTURE_ROOT_SIGNED,
                             FIXTURE_TARGETS_ENVELOPE_EXPIRED,
                             FIXTURE_TARGETS_VERSION) == AKT_ERR_EXPIRED,
              "expired metadata should fail");

    /* older version -> ROLLBACK (min_version above signed.version=5) */
    CHECK_MSG(verify_targets(FIXTURE_ROOT_SIGNED,
                             FIXTURE_TARGETS_ENVELOPE_GOOD,
                             FIXTURE_TARGETS_VERSION + 1) == AKT_ERR_ROLLBACK,
              "downgrade should fail rollback check");

    /* threshold not met: root requires 2 sigs, envelope has 1 -> THRESHOLD */
    CHECK_MSG(verify_targets(FIXTURE_ROOT_SIGNED_THRESHOLD2,
                             FIXTURE_TARGETS_ENVELOPE_GOOD,
                             FIXTURE_TARGETS_VERSION) == AKT_ERR_THRESHOLD,
              "threshold-2 with 1 sig should fail");

    /* missing role -> NO_ROLE */
    CHECK(akt_verify_role_bytes(FIXTURE_ROOT_SIGNED, strlen(FIXTURE_ROOT_SIGNED),
                                "no-such-role",
                                FIXTURE_TARGETS_ENVELOPE_GOOD,
                                strlen(FIXTURE_TARGETS_ENVELOPE_GOOD),
                                FIXTURE_NOW, 0) == AKT_ERR_NO_ROLE);

    /* --- Director target selection --- */
    {
        cJSON *ts = cJSON_Parse(FIXTURE_TARGETS_SIGNED_GOOD);
        CHECK(ts != NULL);
        if (ts) {
            akt_target_t t;
            /* correct target selected by hardware id */
            CHECK(akt_select_target(ts, FIXTURE_HWID, &t) == AKT_OK);
            CHECK_STREQ(t.filepath, FIXTURE_TARGET_PATH);
            CHECK(t.length == (size_t)FIXTURE_TARGET_LEN);
            CHECK(t.version == FIXTURE_TARGET_VERSION);
            char sha[65];
            akt_hex_encode(t.sha256, 32, sha, sizeof(sha));
            CHECK_STREQ(sha, FIXTURE_TARGET_SHA256_HEX);

            /* other hardware id selects the other target */
            akt_target_t t2;
            CHECK(akt_select_target(ts, FIXTURE_OTHER_HWID, &t2) == AKT_OK);
            CHECK(strcmp(t2.filepath, FIXTURE_TARGET_PATH) != 0);

            /* unknown hardware id -> NO_TARGET */
            akt_target_t t3;
            CHECK(akt_select_target(ts, "nonexistent-hwid", &t3) == AKT_ERR_NO_TARGET);
            cJSON_Delete(ts);
        }
    }

    /* --- ISO-8601 parsing sanity --- */
    {
        time_t tt;
        CHECK(akt_parse_iso8601_utc("1970-01-01T00:00:00Z", &tt) == 0 && tt == 0);
        CHECK(akt_parse_iso8601_utc("2000-01-01T00:00:00Z", &tt) == 0 && tt == 946684800);
        CHECK(akt_parse_iso8601_utc("garbage", &tt) != 0);
    }

    TEST_SUMMARY("role");
}
