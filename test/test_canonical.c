/* T1.1 canonical JSON: key-sort, nesting, array order, ints, escaping,
 * plus the gen.py cross-check (C output must equal Python canonical bytes). */
#include "akt_crypto.h"
#include "cJSON.h"
#include "test_util.h"
#include "generated_fixtures.h"
#include <stdlib.h>

/* Parse `in`, canonicalize, assert equal to `expect`. */
static void check_canon(const char *in, const char *expect, const char *label)
{
    cJSON *j = cJSON_Parse(in);
    CHECK_MSG(j != NULL, "parse failed: %s", label);
    if (!j) return;
    size_t n = 0;
    char *c = akt_canonical_json(j, &n);
    CHECK_MSG(c != NULL, "canon NULL: %s", label);
    if (c) {
        CHECK_MSG(strcmp(c, expect) == 0, "%s\n     got: %s\n    want: %s",
                  label, c, expect);
        CHECK_MSG(n == strlen(expect), "%s length mismatch %zu != %zu",
                  label, n, strlen(expect));
        free(c);
    }
    cJSON_Delete(j);
}

int main(void)
{
    /* 1. key sort at multiple nesting levels */
    check_canon("{\"b\":1,\"a\":{\"y\":2,\"x\":3}}",
                "{\"a\":{\"x\":3,\"y\":2},\"b\":1}", "nested key sort");

    /* 2. array order preserved (not sorted) */
    check_canon("{\"a\":[3,1,2],\"z\":[\"c\",\"a\",\"b\"]}",
                "{\"a\":[3,1,2],\"z\":[\"c\",\"a\",\"b\"]}", "array order");

    /* 3. integer formatting — no ".0", large ints intact, negatives */
    check_canon("{\"n\":5,\"len\":1048576,\"neg\":-7,\"zero\":0}",
                "{\"len\":1048576,\"n\":5,\"neg\":-7,\"zero\":0}", "integers");

    /* 4. standard JSON string escaping */
    check_canon("{\"s\":\"a\\\"b\\\\c\\nd\\te\"}",
                "{\"s\":\"a\\\"b\\\\c\\nd\\te\"}", "string escaping");

    /* 5. control char < 0x20 -> \u00xx (lowercase) */
    check_canon("{\"s\":\"\\u0001\\u001f\"}",
                "{\"s\":\"\\u0001\\u001f\"}", "control chars");

    /* 6. booleans / null preserved */
    check_canon("{\"t\":true,\"f\":false,\"n\":null}",
                "{\"f\":false,\"n\":null,\"t\":true}", "bool/null");

    /* 7. realistic TUF `signed` object -> exact bytes */
    check_canon(
        "{\"_type\":\"Targets\",\"version\":5,\"expires\":\"2099-12-31T00:00:00Z\","
        "\"targets\":{\"app.bin\":{\"length\":42,\"hashes\":{\"sha256\":\"ab\"},"
        "\"custom\":{\"hardwareIdentifier\":\"esp32\",\"version\":2}}}}",
        "{\"_type\":\"Targets\",\"expires\":\"2099-12-31T00:00:00Z\","
        "\"targets\":{\"app.bin\":{\"custom\":{\"hardwareIdentifier\":\"esp32\","
        "\"version\":2},\"hashes\":{\"sha256\":\"ab\"},\"length\":42}},\"version\":5}",
        "realistic TUF signed");

    /* 8. CROSS-CHECK vs gen.py canonical bytes (byte-for-byte agreement) */
    {
        cJSON *j = cJSON_Parse(FIXTURE_CANON_INPUT);
        CHECK(j != NULL);
        if (j) {
            size_t n = 0;
            char *c = akt_canonical_json(j, &n);
            CHECK(c != NULL);
            if (c) {
                CHECK_MSG(strcmp(c, FIXTURE_CANON_EXPECTED) == 0,
                          "gen.py cross-check mismatch\n     got: %s\n    want: %s",
                          c, FIXTURE_CANON_EXPECTED);
                free(c);
            }
            cJSON_Delete(j);
        }
    }

    TEST_SUMMARY("canonical");
}
