/*
 * akt_berry_spike.c — S0 host spike for the Aktualino Berry script secondary.
 *
 * Proves the embedding path we will package into components/aktualino_berry:
 *   - create a VM,
 *   - register host native functions (report/log/health_ok/gpio_set) — the seed
 *     of the §7 host API,
 *   - load a single-.be "bundle" source (as bytes, like a delivered target),
 *   - run its top level, call setup() once, then loop() N times,
 *   - observe the heartbeat (health_ok) confirm gate (§8) and a report() uplink.
 *
 * No Aktualino headers yet — this is the raw feasibility check before vendoring.
 */
#include <stdio.h>
#include <string.h>
#include "berry.h"

/* --- host state the "firmware" owns -------------------------------------- */
static int   g_health_ok = 0;      /* set by the script's health_ok() call    */
static int   g_gpio[40]  = {0};    /* fake GPIO latches                        */

/* --- host native functions (seed of the §7 API) -------------------------- */
static int l_log(bvm *vm) {
    const char *msg = (be_top(vm) >= 1) ? be_tostring(vm, 1) : "";
    printf("  [script log] %s\n", msg);
    be_return_nil(vm);
}

static int l_report(bvm *vm) {
    int top = be_top(vm);
    const char *name = (top >= 1) ? be_tostring(vm, 1) : "?";
    if (top >= 2 && be_isint(vm, 2))
        printf("  [report] %s = %lld (int)\n", name, (long long)be_toint(vm, 2));
    else if (top >= 2 && be_isnumber(vm, 2))
        printf("  [report] %s = %g (real)\n", name, be_toreal(vm, 2));
    else
        printf("  [report] %s = %s\n", name, (top >= 2) ? be_tostring(vm, 2) : "nil");
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

/* --- call a zero-arg global function if it exists ------------------------- */
static int call_entry(bvm *vm, const char *name) {
    if (!be_getglobal(vm, name)) { be_pop(vm, 1); return 0; } /* absent: skip  */
    int rc = be_pcall(vm, 0);
    if (rc != 0) {
        fprintf(stderr, "  !! %s() raised: %s\n", name,
                be_top(vm) ? be_tostring(vm, -1) : "?");
    }
    be_pop(vm, 1); /* drop result-or-error */
    return rc;
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
    "  if n == 1 health_ok() end\n"   /* confirm gate: heartbeat on first loop */
    "  if n == 3 gpio_set(2, 0) end\n"
    "end\n";

int main(void) {
    printf("Aktualino Berry spike (engine: Berry v1.1.0)\n");
    bvm *vm = be_vm_new();
    if (!vm) { fprintf(stderr, "be_vm_new failed\n"); return 1; }

    /* register the host API */
    be_regfunc(vm, "log",       l_log);
    be_regfunc(vm, "report",    l_report);
    be_regfunc(vm, "health_ok", l_health_ok);
    be_regfunc(vm, "gpio_set",  l_gpio_set);

    /* load + run the bundle top level (defines setup/loop) */
    if (be_loadstring(vm, BUNDLE_SRC) != 0) {
        fprintf(stderr, "compile error: %s\n", be_tostring(vm, -1));
        be_vm_delete(vm);
        return 2;
    }
    if (be_pcall(vm, 0) != 0) {
        fprintf(stderr, "top-level error: %s\n", be_tostring(vm, -1));
        be_vm_delete(vm);
        return 3;
    }
    be_pop(vm, 1);

    /* scheduler: setup() once, then a few loop() ticks (§6 model) */
    printf("-- setup() --\n");
    call_entry(vm, "setup");
    printf("-- loop() x5 --\n");
    for (int i = 0; i < 5; i++) call_entry(vm, "loop");

    /* the §8 confirm gate the firmware would evaluate */
    printf("-- confirm gate: health_ok seen = %s, gpio2 = %d --\n",
           g_health_ok ? "YES (confirm)" : "NO (would roll back)", g_gpio[2]);

    be_vm_delete(vm);
    return g_health_ok ? 0 : 10;
}
