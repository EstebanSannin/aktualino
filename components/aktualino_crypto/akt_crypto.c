/*
 * akt_crypto.c — portable verify / hash / sign core (T1.2).
 *
 *   - SHA-256           : mbedTLS high-level md API (stable across 2.28 / 3.x).
 *   - Ed25519           : libsodium (verify/sign/keygen).
 *   - RSASSA-PSS-SHA256 : mbedTLS pk_verify_ext.
 *   - base64            : mbedTLS.
 * Dispatch on the TUF `method` string (SPEC §8, PINNED: ed25519 default,
 * rsassa-pss-sha256 fallback).
 */
#include "akt_crypto.h"

#include <stdlib.h>
#include <string.h>

#include "sodium.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/base64.h"

/* ---- lazy libsodium init ----------------------------------------- */
static int ensure_sodium(void)
{
    static int inited = 0;
    if (!inited) {
        if (sodium_init() < 0) return -1;
        inited = 1;
    }
    return 0;
}

/* ---- method string <-> enum -------------------------------------- */
akt_method_t akt_method_from_str(const char *s)
{
    if (!s) return AKT_METHOD_UNKNOWN;
    if (strcmp(s, "ed25519") == 0) return AKT_METHOD_ED25519;
    if (strcmp(s, "rsassa-pss-sha256") == 0) return AKT_METHOD_RSASSA_PSS_SHA256;
    return AKT_METHOD_UNKNOWN;
}

const char *akt_method_to_str(akt_method_t m)
{
    switch (m) {
        case AKT_METHOD_ED25519:           return "ed25519";
        case AKT_METHOD_RSASSA_PSS_SHA256: return "rsassa-pss-sha256";
        default:                           return "unknown";
    }
}

/* ---- SHA-256 ----------------------------------------------------- */
int akt_sha256(const void *data, size_t len, uint8_t out32[32])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return -1;
    if (mbedtls_md(info, (const unsigned char *)data, len, out32) != 0) return -1;
    return 0;
}

/* ---- Ed25519 ----------------------------------------------------- */
static bool verify_ed25519(const uint8_t *pk, size_t pk_len,
                           const void *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len)
{
    if (pk_len != crypto_sign_PUBLICKEYBYTES || sig_len != crypto_sign_BYTES) return false;
    if (ensure_sodium() != 0) return false;
    return crypto_sign_verify_detached(sig, (const unsigned char *)msg, msg_len, pk) == 0;
}

int akt_sign_ed25519(const uint8_t sk[64], const void *msg, size_t msg_len,
                     uint8_t out_sig[64])
{
    if (ensure_sodium() != 0) return -1;
    if (crypto_sign_detached(out_sig, NULL, (const unsigned char *)msg, msg_len, sk) != 0)
        return -1;
    return 0;
}

int akt_keygen_ed25519(uint8_t pk[32], uint8_t sk[64])
{
    if (ensure_sodium() != 0) return -1;
    if (crypto_sign_keypair(pk, sk) != 0) return -1;
    return 0;
}

int akt_keyid_ed25519(const uint8_t pk[32], char out_hex[65])
{
    /* ota-tuf keyId = sha256( X.509 SubjectPublicKeyInfo DER of the raw key ).
     * The Ed25519 SPKI DER is a fixed 12-byte prefix followed by the 32 raw
     * public-key bytes (44 bytes total). */
    static const uint8_t spki_prefix[12] = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    uint8_t der[44];
    memcpy(der, spki_prefix, 12);
    memcpy(der + 12, pk, 32);
    uint8_t h[32];
    if (akt_sha256(der, sizeof(der), h) != 0) return -1;
    return akt_hex_encode(h, 32, out_hex, 65);
}

/* ---- RSASSA-PSS-SHA256 ------------------------------------------- */
static bool verify_rsa_pss(const uint8_t *pem, size_t pem_len,
                           const void *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len)
{
    /* mbedtls_pk_parse_public_key wants a NUL-terminated PEM and a length that
     * includes the terminating NUL. Make a safe copy. */
    size_t n = pem_len;
    while (n > 0 && pem[n - 1] == '\0') n--;   /* trim any trailing NULs */
    uint8_t *buf = (uint8_t *)malloc(n + 1);
    if (!buf) return false;
    memcpy(buf, pem, n);
    buf[n] = '\0';

    bool ok = false;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, buf, n + 1) == 0) {
        uint8_t hash[32];
        if (akt_sha256(msg, msg_len, hash) == 0) {
            mbedtls_pk_rsassa_pss_options opts;
            opts.mgf1_hash_id = MBEDTLS_MD_SHA256;
            opts.expected_salt_len = MBEDTLS_RSA_SALT_LEN_ANY;
            int r = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &opts, &pk,
                                          MBEDTLS_MD_SHA256, hash, 32,
                                          sig, sig_len);
            ok = (r == 0);
        }
    }
    mbedtls_pk_free(&pk);
    free(buf);
    return ok;
}

/* ---- verify dispatch --------------------------------------------- */
bool akt_verify(const char *method,
                const uint8_t *pubkey, size_t pubkey_len,
                const void *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len)
{
    switch (akt_method_from_str(method)) {
        case AKT_METHOD_ED25519:
            return verify_ed25519(pubkey, pubkey_len, msg, msg_len, sig, sig_len);
        case AKT_METHOD_RSASSA_PSS_SHA256:
            return verify_rsa_pss(pubkey, pubkey_len, msg, msg_len, sig, sig_len);
        default:
            return false;
    }
}

bool akt_verify_with_pubkey(const akt_pubkey_t *key,
                            const void *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len)
{
    if (!key) return false;
    switch (key->method) {
        case AKT_METHOD_ED25519:
            return verify_ed25519(key->ed25519_pub, 32, msg, msg_len, sig, sig_len);
        case AKT_METHOD_RSASSA_PSS_SHA256:
            if (!key->pem) return false;
            return verify_rsa_pss((const uint8_t *)key->pem, strlen(key->pem),
                                  msg, msg_len, sig, sig_len);
        default:
            return false;
    }
}

/* ---- TUF key parse ----------------------------------------------- */
int akt_parse_tuf_key(const cJSON *key_obj, akt_pubkey_t *out)
{
    if (!key_obj || !out) return -1;
    memset(out, 0, sizeof(*out));

    const cJSON *keytype = cJSON_GetObjectItemCaseSensitive(key_obj, "keytype");
    const cJSON *keyval  = cJSON_GetObjectItemCaseSensitive(key_obj, "keyval");
    if (!cJSON_IsString(keytype) || !cJSON_IsObject(keyval)) return -1;
    const cJSON *pub = cJSON_GetObjectItemCaseSensitive(keyval, "public");
    if (!cJSON_IsString(pub)) return -1;

    /* keytype is upper-case in TUF ("ED25519", "RSA"); be tolerant of case. */
    const char *kt = keytype->valuestring;
    if (strcasecmp(kt, "ED25519") == 0) {
        out->method = AKT_METHOD_ED25519;
        size_t n = 0;
        if (akt_hex_decode(pub->valuestring, out->ed25519_pub, 32, &n) != 0 || n != 32)
            return -1;
        return 0;
    }
    if (strcasecmp(kt, "RSA") == 0) {
        out->method = AKT_METHOD_RSASSA_PSS_SHA256;
        out->pem = strdup(pub->valuestring);
        return out->pem ? 0 : -1;
    }
    return -1;  /* ecPrime256v1 and others rejected (SPEC §8). */
}

void akt_pubkey_free(akt_pubkey_t *k)
{
    if (!k) return;
    free(k->pem);
    k->pem = NULL;
}

/* ---- hex --------------------------------------------------------- */
static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int akt_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!hex || !out) return -1;
    size_t hl = strlen(hex);
    if (hl % 2 != 0) return -1;
    size_t n = hl / 2;
    if (n > out_cap) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hexval((unsigned char)hex[2 * i]);
        int lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (out_len) *out_len = n;
    return 0;
}

int akt_hex_encode(const uint8_t *in, size_t len, char *out, size_t out_cap)
{
    static const char *H = "0123456789abcdef";
    if (out_cap < 2 * len + 1) return -1;
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = H[in[i] >> 4];
        out[2 * i + 1] = H[in[i] & 0x0f];
    }
    out[2 * len] = '\0';
    return 0;
}

/* ---- base64 (mbedTLS) -------------------------------------------- */
int akt_base64_decode(const char *b64, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!b64 || !out) return -1;
    size_t olen = 0;
    int r = mbedtls_base64_decode(out, out_cap, &olen,
                                  (const unsigned char *)b64, strlen(b64));
    if (r != 0) return -1;
    if (out_len) *out_len = olen;
    return 0;
}

int akt_base64_encode(const uint8_t *in, size_t len, char *out, size_t out_cap)
{
    size_t olen = 0;
    int r = mbedtls_base64_encode((unsigned char *)out, out_cap, &olen, in, len);
    return r == 0 ? 0 : -1;
}
