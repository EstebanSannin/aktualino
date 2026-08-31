/*
 * akt_canonical.c — canonical JSON serializer (SPEC Appendix A, T1.1).
 *
 * Byte-exact reproduction of the OTA-Connect/Uptane canonical JSON (recursive
 * key-sort + circe `noSpaces`):
 *   - recursively sort object keys ascending (unsigned bytewise == UTF-16
 *     code-unit for ASCII, the only case TUF uses),
 *   - preserve array order,
 *   - minified: no whitespace, ',' and ':' separators,
 *   - JSON string escaping: \" \\ \b \f \n \r \t and other control chars as
 *     \u00xx (lowercase); '/' NOT escaped; non-ASCII passed through as UTF-8,
 *   - numbers emitted verbatim as integers when integral (no ".0") — TUF numbers
 *     are always small ints (version/length/threshold). cJSON does not retain
 *     the source text of a number, so we reconstruct: integral -> "%lld",
 *     otherwise "%.17g" (a case TUF never produces; documented caveat).
 */
#include "akt_crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ---- growable byte buffer ---------------------------------------- */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    int    err;
} sb_t;

static void sb_reserve(sb_t *sb, size_t extra)
{
    if (sb->err) return;
    if (sb->len + extra + 1 <= sb->cap) return;
    size_t ncap = sb->cap ? sb->cap : 128;
    while (ncap < sb->len + extra + 1) ncap *= 2;
    char *nb = (char *)realloc(sb->buf, ncap);
    if (!nb) { sb->err = 1; return; }
    sb->buf = nb;
    sb->cap = ncap;
}

static void sb_putc(sb_t *sb, char c)
{
    sb_reserve(sb, 1);
    if (sb->err) return;
    sb->buf[sb->len++] = c;
}

static void sb_write(sb_t *sb, const char *s, size_t n)
{
    sb_reserve(sb, n);
    if (sb->err) return;
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
}

static void sb_puts(sb_t *sb, const char *s) { sb_write(sb, s, strlen(s)); }

/* ---- string escaping (circe-compatible) -------------------------- */
static void write_json_string(sb_t *sb, const char *s)
{
    sb_putc(sb, '"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '"':  sb_write(sb, "\\\"", 2); break;
            case '\\': sb_write(sb, "\\\\", 2); break;
            case '\b': sb_write(sb, "\\b", 2);  break;
            case '\f': sb_write(sb, "\\f", 2);  break;
            case '\n': sb_write(sb, "\\n", 2);  break;
            case '\r': sb_write(sb, "\\r", 2);  break;
            case '\t': sb_write(sb, "\\t", 2);  break;
            default:
                if (c < 0x20) {
                    char u[7];
                    snprintf(u, sizeof(u), "\\u%04x", c);
                    sb_write(sb, u, 6);
                } else {
                    /* printable ASCII or a UTF-8 continuation/lead byte:
                     * pass through verbatim (circe does not escape non-ASCII). */
                    sb_putc(sb, (char)c);
                }
                break;
        }
    }
    sb_putc(sb, '"');
}

/* ---- number formatting ------------------------------------------- */
static void write_json_number(sb_t *sb, const cJSON *item)
{
    double d = item->valuedouble;
    char tmp[32];
    if (isfinite(d) && d == floor(d) && fabs(d) < 9.2e18) {
        long long v = (long long)d;
        snprintf(tmp, sizeof(tmp), "%lld", v);
    } else {
        /* Non-integral: TUF metadata never hits this path. Emit a compact repr. */
        snprintf(tmp, sizeof(tmp), "%.17g", d);
    }
    sb_puts(sb, tmp);
}

/* ---- key sort ---------------------------------------------------- */
static int keycmp(const void *a, const void *b)
{
    const cJSON *ca = *(const cJSON *const *)a;
    const cJSON *cb = *(const cJSON *const *)b;
    /* Unsigned bytewise compare == UTF-16 code-unit order for ASCII keys. */
    return strcmp(ca->string ? ca->string : "", cb->string ? cb->string : "");
}

/* ---- recursive emit ---------------------------------------------- */
static void emit(sb_t *sb, const cJSON *item)
{
    if (sb->err) return;
    if (!item) { sb_puts(sb, "null"); return; }

    switch (item->type & 0xFF) {
        case cJSON_NULL:   sb_puts(sb, "null");  break;
        case cJSON_False:  sb_puts(sb, "false"); break;
        case cJSON_True:   sb_puts(sb, "true");  break;
        case cJSON_Number: write_json_number(sb, item); break;
        case cJSON_String: write_json_string(sb, item->valuestring ? item->valuestring : ""); break;
        case cJSON_Raw:
            /* Raw is already-serialized JSON; emit as-is (not used for TUF). */
            if (item->valuestring) sb_puts(sb, item->valuestring);
            break;
        case cJSON_Array: {
            sb_putc(sb, '[');
            int first = 1;
            for (const cJSON *c = item->child; c; c = c->next) {
                if (!first) sb_putc(sb, ',');
                first = 0;
                emit(sb, c);
            }
            sb_putc(sb, ']');
            break;
        }
        case cJSON_Object: {
            /* Collect children, sort by key, emit. */
            size_t n = 0;
            for (const cJSON *c = item->child; c; c = c->next) n++;
            const cJSON **kids = NULL;
            if (n) {
                kids = (const cJSON **)malloc(n * sizeof(*kids));
                if (!kids) { sb->err = 1; return; }
                size_t i = 0;
                for (const cJSON *c = item->child; c; c = c->next) kids[i++] = c;
                qsort(kids, n, sizeof(*kids), keycmp);
            }
            sb_putc(sb, '{');
            for (size_t i = 0; i < n; i++) {
                if (i) sb_putc(sb, ',');
                write_json_string(sb, kids[i]->string ? kids[i]->string : "");
                sb_putc(sb, ':');
                emit(sb, kids[i]);
            }
            sb_putc(sb, '}');
            free(kids);
            break;
        }
        default:
            sb_puts(sb, "null");
            break;
    }
}

char *akt_canonical_json(const cJSON *obj, size_t *out_len)
{
    if (!obj) return NULL;
    sb_t sb = {0};
    emit(&sb, obj);
    if (sb.err) { free(sb.buf); return NULL; }
    /* Ensure a NUL terminator. */
    sb_reserve(&sb, 1);
    if (sb.err) { free(sb.buf); return NULL; }
    sb.buf[sb.len] = '\0';
    if (out_len) *out_len = sb.len;
    return sb.buf;
}
