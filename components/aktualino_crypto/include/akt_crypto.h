/*
 * akt_crypto — PORTABLE Uptane crypto core (host + ESP32 target).
 *
 * This header is the security heart shared by the host unit tests and the
 * on-target ESP components. It deliberately depends ONLY on portable libraries:
 *   - cJSON  (host: libcjson-dev / vendored; target: ESP-IDF `json` component)
 *   - mbedTLS (SHA-256, RSASSA-PSS, base64)
 *   - libsodium (Ed25519 verify/sign/keygen)
 * It must NOT include any ESP-only header (no esp_err.h) so that the exact same
 * object code compiles for the host and both ESP targets. The thin esp_err_t
 * wrappers in aktualino_crypto.c adapt these to the ESP component API.
 *
 * Return convention: 0 == success, negative == failure (unless noted).
 * Canonical JSON follows SPEC Appendix A (recursive key-sort + circe `noSpaces`),
 * matching the OTA-Connect/Uptane backend's canonical-JSON form.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * Canonical JSON (SPEC Appendix A)
 *
 * Recursively sort object keys ascending (bytewise == UTF-16 code-unit order
 * for ASCII keys — the only case TUF uses; see note below), preserve array
 * order, minified (no whitespace), standard JSON string escaping, numbers
 * emitted as integers when integral (no ".0") to match circe `noSpaces`.
 *
 * Returns a freshly malloc()'d NUL-terminated buffer (caller frees) holding the
 * canonical bytes; *out_len (optional) receives the length excluding the NUL.
 * Returns NULL on allocation failure or NULL input.
 *
 * NOTE on key ordering: circe sorts with Scala's String ordering (compareTo),
 * i.e. by UTF-16 code unit. For ASCII keys that is identical to unsigned
 * bytewise ordering, which is what we use. All TUF/Uptane metadata keys are
 * ASCII, so this is exact; non-ASCII object keys (never emitted by the backend)
 * would need UTF-16 reordering to stay byte-exact.
 * ------------------------------------------------------------------ */
char *akt_canonical_json(const cJSON *obj, size_t *out_len);

/* ------------------------------------------------------------------ *
 * Hashing
 * ------------------------------------------------------------------ */

/* One-shot SHA-256 of `data` (len bytes) into out32. Returns 0 on success. */
int akt_sha256(const void *data, size_t len, uint8_t out32[32]);

/* ------------------------------------------------------------------ *
 * Signature verification / signing
 * ------------------------------------------------------------------ */

typedef enum {
    AKT_METHOD_ED25519 = 0,          /* "ed25519" (default)           */
    AKT_METHOD_RSASSA_PSS_SHA256,    /* "rsassa-pss-sha256" (fallback)*/
    AKT_METHOD_UNKNOWN,
} akt_method_t;

akt_method_t akt_method_from_str(const char *s);
const char  *akt_method_to_str(akt_method_t m);

/*
 * Verify a detached signature over msg[msg_len], dispatched on `method`:
 *   - "ed25519":            pubkey = 32 raw bytes, sig = 64 raw bytes.
 *   - "rsassa-pss-sha256":  pubkey = PEM public key (NUL-terminated; pubkey_len
 *                           may include or exclude the NUL), sig = raw PSS bytes.
 * Returns true iff the signature is valid. Never aborts on malformed input.
 */
bool akt_verify(const char *method,
                const uint8_t *pubkey, size_t pubkey_len,
                const void *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len);

/* Ed25519 detached sign. sk = 64-byte libsodium secret key. Returns 0. */
int akt_sign_ed25519(const uint8_t sk[64],
                     const void *msg, size_t msg_len,
                     uint8_t out_sig[64]);

/* Fresh Ed25519 keypair: pk = 32 bytes, sk = 64 bytes. Returns 0. */
int akt_keygen_ed25519(uint8_t pk[32], uint8_t sk[64]);

/*
 * TUF keyid for an Ed25519 public key, matching the OTA-Connect ota-tuf keyId:
 *   keyid = sha256( X.509 SubjectPublicKeyInfo DER of the raw key ), hex.
 * out_hex must hold >= 65 bytes (64 hex chars + NUL). Returns 0.
 */
int akt_keyid_ed25519(const uint8_t pk[32], char out_hex[65]);

/* ------------------------------------------------------------------ *
 * TUF key parsing: {keytype, keyval:{public}}  (SPEC Appendix A / §8)
 * ------------------------------------------------------------------ */
typedef struct {
    akt_method_t method;          /* ED25519 or RSASSA_PSS_SHA256      */
    uint8_t      ed25519_pub[32]; /* valid iff method == ED25519       */
    char        *pem;             /* malloc'd PEM iff method == RSA...  */
} akt_pubkey_t;

/*
 * Parse a TUF key object. For ED25519, keyval.public is 32-byte hex; for RSA,
 * keyval.public is a PEM public key. Returns 0 on success (caller must
 * akt_pubkey_free). Returns negative on unknown/invalid key.
 */
int  akt_parse_tuf_key(const cJSON *key_obj, akt_pubkey_t *out);
void akt_pubkey_free(akt_pubkey_t *k);

/* Verify a signature entry against a parsed TUF key over canonical bytes. */
bool akt_verify_with_pubkey(const akt_pubkey_t *key,
                            const void *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len);

/* ------------------------------------------------------------------ *
 * Encoding helpers
 * ------------------------------------------------------------------ */

/* Lowercase hex. Decode returns 0 on success; *out_len = decoded byte count. */
int akt_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len);
int akt_hex_encode(const uint8_t *in, size_t len, char *out, size_t out_cap);

/* base64 (standard alphabet, mbedTLS). Return 0 on success. */
int akt_base64_decode(const char *b64, uint8_t *out, size_t out_cap, size_t *out_len);
int akt_base64_encode(const uint8_t *in, size_t len, char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
