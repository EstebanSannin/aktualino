/*
 * aktualino_berry.h — thin embedding API around the vendored Berry VM.
 *
 * This is the seam the script secondary (components/aktualino_script, S3) sits
 * on: create a runtime, register host-API natives, load a single-.be bundle,
 * and drive the setup()/loop() scheduler (SPEC berry-secondary §6). It owns none
 * of the Uptane/delivery logic — it is purely "run this verified bundle".
 *
 * Host-API binding modules write ordinary Berry native functions (int fn(bvm*),
 * reading args + returning via the be_* API), so this header intentionally
 * exposes the Berry `bvm`/`bntvfunc` types — that coupling is expected for any
 * code that binds C into Berry.
 */
#pragma once

#include <stddef.h>
#include "berry.h"   /* bvm, bntvfunc */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct akt_berry akt_berry_t;

/* Return codes for entry-point calls. */
typedef enum {
    AKT_BERRY_OK     =  0,   /* entry ran without error                       */
    AKT_BERRY_ABSENT =  1,   /* no such global (e.g. bundle defines no loop)  */
    AKT_BERRY_ERROR  = -1,   /* entry raised — see akt_berry_last_error()      */
} akt_berry_rc;

/* Create / destroy a runtime (one per script secondary). NULL on OOM. */
akt_berry_t *akt_berry_new(void);
void         akt_berry_free(akt_berry_t *rt);

/* The underlying VM, for host-API binding modules that push natives directly. */
bvm *akt_berry_vm(akt_berry_t *rt);

/* Register a host native function as a Berry global (seed of the §7 host API). */
void akt_berry_register(akt_berry_t *rt, const char *name, bntvfunc fn);

/*
 * Load a single-.be bundle: compile `src`/`len` and run its top level (which
 * defines setup()/loop()). `name` labels the source in error/trace messages
 * (e.g. the bundle target path); may be NULL. Returns 0 on success, <0 on a
 * compile or top-level runtime error (message via akt_berry_last_error()).
 */
int akt_berry_load(akt_berry_t *rt, const char *name, const void *src, size_t len);

/*
 * Call a zero-argument global entry (e.g. "setup", "loop") if it is defined.
 * AKT_BERRY_ABSENT is not an error — a bundle need not define every entry.
 */
akt_berry_rc akt_berry_call(akt_berry_t *rt, const char *entry);

/* Last error message; valid until the next akt_berry_* call. "" if none. */
const char *akt_berry_last_error(akt_berry_t *rt);

#ifdef __cplusplus
}
#endif
