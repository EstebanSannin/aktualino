/*
 * akt_berry_spike.c — S0 host test for components/aktualino_berry.
 *
 * Exercises the component's embedding API (aktualino_berry.h) — the same seam
 * components/aktualino_script will use — with NO ESP-IDF dependency:
 *   - create a runtime,
 *   - register host-API natives (log/report/gpio_set/health_ok) — seed of §7,
 *   - load a single-.be "bundle" (as delivered target bytes),
 *   - run setup() once, then loop() N times (the §6 scheduler),
 *   - evaluate the §8 heartbeat confirm gate,
 *   - and confirm a bad bundle surfaces an error (not a crash).
 *
 * Exit 0 = all assertions passed.
 */
#include <stdio.h>
#include <string.h>
#include "aktualino_berry.h"

/* --- host state the "firmware" owns -------------------------------------- */
static int g_health_ok = 0;
static int g_gpio[40]  = {0};
static int g_reports   = 0;

/* --- host native functions (seed of the §7 API) -------------------------- */
static int l_log(bvm *vm) {
    printf("  [script log] %s\n", (be_top(vm) >= 1) ? be_tostring(vm, 1) : "");
    be_return_nil(vm);
}
static int l_report(bvm *vm) {
    int top = be_top(vm);
    const char *name = (top >= 1) ? be_tostring(vm, 1) : "?";
    if (top >= 2 && be_isint(vm, 2))
        printf("  [report] %s = %lld\n", name, (long long)be_toint(vm, 2));
    else
        printf("  [report] %s = %s\n", name, (top >= 2) ? be_tostring(vm, 2) : "nil");
    g_reports++;
    be_return_nil(vm);
}
static int l_health_ok(bvm *vm) {
    g_health_ok = 1;
    printf("  [health] heartbeat received\n");
    be_return_nil(vm);
}
static int l_gpio_set(bvm *vm) {
    if (be_top(vm) >= 2 && be_isint(vm, 1) && be_isint(vm, 2)) {
        bint pin = be_toint(vm, 1), lvl = be_toint(vm, 2);
        if (pin >= 0 && pin < 40) g_gpio[pin] = (lvl != 0);
        printf("  [gpio] pin %lld <- %lld\n", (long long)pin, (long long)lvl);
    }
    be_return_nil(vm);
}

static void register_host_api(akt_berry_t *rt) {
    akt_berry_register(rt, "log",       l_log);
    akt_berry_register(rt, "report",    l_report);
    akt_berry_register(rt, "health_ok", l_health_ok);
    akt_berry_register(rt, "gpio_set",  l_gpio_set);
}

/* --- a single-.be "bundle" (what a delivered target would contain) -------- */
static const char BUNDLE_SRC[] =
    "var n = 0\n"
    "def setup()\n"
    "  log('setup: bundle starting')\n"
    "  gpio_set(2, 1)\n"
    "end\n"
    "def loop()\n"
    "  n = n + 1\n"
    "  report('tick', n)\n"
    "  if n == 1 health_ok() end\n"
    "  if n == 3 gpio_set(2, 0) end\n"
    "end\n";

#define CHECK(cond, msg) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: %s\n", (msg)); return 1; } } while (0)

static int test_good_bundle(void) {
    printf("== good bundle ==\n");
    akt_berry_t *rt = akt_berry_new();
    CHECK(rt, "akt_berry_new");
    register_host_api(rt);

    CHECK(akt_berry_load(rt, "good.be", BUNDLE_SRC, strlen(BUNDLE_SRC)) == 0,
          "load good bundle");

    printf("-- setup() --\n");
    CHECK(akt_berry_call(rt, "setup") == AKT_BERRY_OK, "setup ok");
    CHECK(g_gpio[2] == 1, "setup drove gpio2 high");

    printf("-- loop() x5 --\n");
    for (int i = 0; i < 5; i++)
        CHECK(akt_berry_call(rt, "loop") == AKT_BERRY_OK, "loop ok");

    /* §8 confirm gate the firmware would evaluate */
    printf("-- confirm gate: health_ok=%s gpio2=%d reports=%d --\n",
           g_health_ok ? "YES" : "NO", g_gpio[2], g_reports);
    CHECK(g_health_ok == 1, "heartbeat seen (would confirm)");
    CHECK(g_gpio[2] == 0,   "loop drove gpio2 low on tick 3");
    CHECK(g_reports == 5,   "five reports uplinked");

    /* absent entry is not an error */
    CHECK(akt_berry_call(rt, "on_message") == AKT_BERRY_ABSENT, "absent entry skipped");

    akt_berry_free(rt);
    return 0;
}

static int test_bad_bundle(void) {
    printf("== bad bundle (syntax error) ==\n");
    akt_berry_t *rt = akt_berry_new();
    CHECK(rt, "akt_berry_new");
    register_host_api(rt);

    const char *bad = "def setup(\n  broken syntax !!\n";  /* won't compile */
    CHECK(akt_berry_load(rt, "bad.be", bad, strlen(bad)) < 0, "bad bundle rejected");
    CHECK(strlen(akt_berry_last_error(rt)) > 0, "error message captured");
    printf("  rejected with: %s\n", akt_berry_last_error(rt));

    akt_berry_free(rt);
    return 0;
}

static int test_runtime_error(void) {
    printf("== runtime error in loop() surfaces (not a crash) ==\n");
    akt_berry_t *rt = akt_berry_new();
    CHECK(rt, "akt_berry_new");
    register_host_api(rt);

    const char *src =
        "def setup() end\n"
        "def loop()\n  return nil + 1\n end\n";   /* type error at runtime */
    CHECK(akt_berry_load(rt, "rt.be", src, strlen(src)) == 0, "loads fine");
    CHECK(akt_berry_call(rt, "setup") == AKT_BERRY_OK, "setup ok");
    CHECK(akt_berry_call(rt, "loop") == AKT_BERRY_ERROR, "loop error surfaced");
    CHECK(strlen(akt_berry_last_error(rt)) > 0, "error message captured");
    printf("  loop() raised: %s\n", akt_berry_last_error(rt));

    akt_berry_free(rt);
    return 0;
}

int main(void) {
    printf("Aktualino Berry embedding test (engine: Berry v1.1.0)\n\n");
    if (test_good_bundle())    return 1;
    printf("\n");
    if (test_bad_bundle())     return 1;
    printf("\n");
    if (test_runtime_error())  return 1;
    printf("\nALL PASS\n");
    return 0;
}
