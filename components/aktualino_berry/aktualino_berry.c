/*
 * aktualino_berry.c — embedding wrapper around the vendored Berry VM.
 * See aktualino_berry.h for the contract.
 */
#include "aktualino_berry.h"

#include <stdlib.h>
#include <string.h>

struct akt_berry {
    bvm *vm;
    char err[160];   /* last error message, captured off the Berry stack */
};

/* Copy the value on top of the Berry stack into rt->err, then leave it there
 * for the caller to pop (keeps stack handling in one place). */
static void capture_error(akt_berry_t *rt)
{
    const char *msg = be_tostring(rt->vm, -1);
    if (msg) {
        strncpy(rt->err, msg, sizeof(rt->err) - 1);
        rt->err[sizeof(rt->err) - 1] = '\0';
    } else {
        rt->err[0] = '\0';
    }
}

akt_berry_t *akt_berry_new(void)
{
    akt_berry_t *rt = calloc(1, sizeof(*rt));
    if (!rt) return NULL;
    rt->vm = be_vm_new();
    if (!rt->vm) { free(rt); return NULL; }
    return rt;
}

void akt_berry_free(akt_berry_t *rt)
{
    if (!rt) return;
    if (rt->vm) be_vm_delete(rt->vm);
    free(rt);
}

bvm *akt_berry_vm(akt_berry_t *rt)
{
    return rt ? rt->vm : NULL;
}

void akt_berry_register(akt_berry_t *rt, const char *name, bntvfunc fn)
{
    be_regfunc(rt->vm, name, fn);
}

int akt_berry_load(akt_berry_t *rt, const char *name, const void *src, size_t len)
{
    rt->err[0] = '\0';
    if (be_loadbuffer(rt->vm, name ? name : "bundle", (const char *)src, len) != 0) {
        capture_error(rt);          /* compile error on the stack */
        be_pop(rt->vm, 1);
        return -1;
    }
    if (be_pcall(rt->vm, 0) != 0) { /* run the top level (defines setup/loop) */
        capture_error(rt);          /* runtime error on the stack */
        be_pop(rt->vm, 1);
        return -1;
    }
    be_pop(rt->vm, 1);              /* drop the top-level result */
    return 0;
}

akt_berry_rc akt_berry_call(akt_berry_t *rt, const char *entry)
{
    rt->err[0] = '\0';
    if (!be_getglobal(rt->vm, entry)) {
        be_pop(rt->vm, 1);          /* nil pushed for the missing global */
        return AKT_BERRY_ABSENT;
    }
    if (be_pcall(rt->vm, 0) != 0) {
        capture_error(rt);
        be_pop(rt->vm, 1);
        return AKT_BERRY_ERROR;
    }
    be_pop(rt->vm, 1);              /* drop the return value */
    return AKT_BERRY_OK;
}

const char *akt_berry_last_error(akt_berry_t *rt)
{
    return rt ? rt->err : "";
}
