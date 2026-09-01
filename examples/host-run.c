/*
 * host-run.c — run an Aktualino Berry bundle on your laptop (no ESP32).
 *
 * Loads a .be file through the exact embedding API the device uses
 * (aktualino_berry), registers stub versions of the host API (GPIO/millis/etc.
 * just print), runs setup() + N loop() cycles, and reports success/failure — so
 * you can catch syntax/logic errors before publishing a bundle to the cloud.
 *
 * Built + run by examples/run.sh. See docs/bundles.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "aktualino_berry.h"

static struct timeval g_start;
static long now_ms(void) {
    struct timeval t; gettimeofday(&t, NULL);
    return (t.tv_sec - g_start.tv_sec) * 1000 + (t.tv_usec - g_start.tv_usec) / 1000;
}

static int l_log(bvm *vm) { printf("  [log] %s\n", be_top(vm) >= 1 ? be_tostring(vm, 1) : ""); be_return_nil(vm); }
static int l_report(bvm *vm) {
    int t = be_top(vm);
    const char *n = (t >= 1) ? be_tostring(vm, 1) : "?";
    if (t >= 2 && be_isint(vm, 2)) printf("  [report] %s = %lld\n", n, (long long)be_toint(vm, 2));
    else printf("  [report] %s = %s\n", n, (t >= 2) ? be_tostring(vm, 2) : "nil");
    be_return_nil(vm);
}
static int l_health_ok(bvm *vm) { printf("  [health_ok]\n"); be_return_nil(vm); }
static int l_gpio_mode(bvm *vm) {
    if (be_top(vm) >= 2) printf("  [gpio_mode] pin %lld mode %lld\n",
        (long long)be_toint(vm, 1), (long long)be_toint(vm, 2));
    be_return_nil(vm);
}
static int l_gpio_set(bvm *vm) {
    if (be_top(vm) >= 2) printf("  [gpio_set] pin %lld <- %lld\n",
        (long long)be_toint(vm, 1), (long long)be_toint(vm, 2));
    be_return_nil(vm);
}
static int l_gpio_get(bvm *vm) { be_pushint(vm, 0); be_return(vm); }   /* stub: reads low */
static int l_millis(bvm *vm)   { be_pushint(vm, (bint)now_ms()); be_return(vm); }

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return NULL; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = malloc(n + 1);
    if (buf && fread(buf, 1, n, f) == (size_t)n) { buf[n] = 0; *len = n; }
    else { free(buf); buf = NULL; }
    fclose(f);
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <bundle.be> [loops]\n", argv[0]); return 2; }
    int loops = (argc >= 3) ? atoi(argv[2]) : 12;
    gettimeofday(&g_start, NULL);

    size_t len = 0;
    char *src = read_file(argv[1], &len);
    if (!src) return 2;

    printf("== running %s (%d loops, ~150ms apart) ==\n", argv[1], loops);
    akt_berry_t *rt = akt_berry_new();
    akt_berry_register(rt, "log", l_log);
    akt_berry_register(rt, "report", l_report);
    akt_berry_register(rt, "health_ok", l_health_ok);
    akt_berry_register(rt, "gpio_mode", l_gpio_mode);
    akt_berry_register(rt, "gpio_set", l_gpio_set);
    akt_berry_register(rt, "gpio_get", l_gpio_get);
    akt_berry_register(rt, "millis", l_millis);

    int rc = 0;
    if (akt_berry_load(rt, argv[1], src, len) != 0) {
        fprintf(stderr, "COMPILE ERROR: %s\n", akt_berry_last_error(rt)); rc = 1;
    } else if (akt_berry_call(rt, "setup") == AKT_BERRY_ERROR) {
        fprintf(stderr, "setup() ERROR: %s\n", akt_berry_last_error(rt)); rc = 1;
    } else {
        for (int i = 0; i < loops && rc == 0; i++) {
            usleep(150 * 1000);
            if (akt_berry_call(rt, "loop") == AKT_BERRY_ERROR) {
                fprintf(stderr, "loop() ERROR: %s\n", akt_berry_last_error(rt)); rc = 1;
            }
        }
    }
    akt_berry_free(rt);
    free(src);
    printf(rc == 0 ? "== OK ==\n" : "== FAILED ==\n");
    return rc;
}
