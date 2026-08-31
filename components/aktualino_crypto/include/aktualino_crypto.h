/*
 * aktualino_crypto — signature verify, hashing, manifest signing (SPEC §5, §8).
 *
 * STATUS: Phase-0 compiling stub. Functions return ESP_ERR_NOT_SUPPORTED until
 * T1.2 / T1.4. The SHA-256 helpers are the exception the OTA path already needs
 * a streaming hash for (that lives in aktualino_ota); here we expose one-shot
 * hashing plus the verify/sign surface.
 *
 * Primitives (SPEC §8, PINNED):
 *   - Verify: Ed25519 is the DEFAULT metadata/manifest method (libsodium);
 *     rsassa-pss-sha256 is the secondary path (mbedTLS). Dispatch on the
 *     metadata's declared `method` string.
 *   - Hash: SHA-256 (mbedTLS, HW-accelerated).
 *   - Sign: Ed25519 with the on-device ECU key (device manifest, SPEC §7.8).
 *
 * The verify functions take the canonical-JSON bytes of the `signed` sub-object
 * (produced by aktualino_uptane) as the message — NOT the raw envelope.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Signature method as it appears in a TUF signature entry (SPEC Appendix A). */
typedef enum {
    AKT_SIG_ED25519 = 0,          /* "ed25519" (default) */
    AKT_SIG_RSASSA_PSS_SHA256,    /* "rsassa-pss-sha256" (secondary) */
    AKT_SIG_UNKNOWN,
} aktualino_sig_method_t;

/* Map a TUF method string to the enum; AKT_SIG_UNKNOWN if unrecognized. */
aktualino_sig_method_t aktualino_crypto_method_from_str(const char *method);

/* One-shot SHA-256 of `data` into `out32`. */
esp_err_t aktualino_crypto_sha256(const void *data, size_t len,
                                  uint8_t out32[32]);

/*
 * Verify a detached signature over `msg` using `pubkey`.
 *   - Ed25519: pubkey is the 32-byte raw key (or hex; see impl), sig is 64 bytes.
 *   - RSASSA-PSS-SHA256: pubkey is a DER/PEM SPKI, sig is the PSS signature.
 * Returns ESP_OK on a valid signature, ESP_ERR_INVALID_CRC on mismatch.
 */
esp_err_t aktualino_crypto_verify(aktualino_sig_method_t method,
                                  const uint8_t *pubkey, size_t pubkey_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const void *msg, size_t msg_len);

/*
 * Sign `msg` with the on-device Ed25519 ECU key, writing a 64-byte signature to
 * `out_sig`. Used for the double-signed device manifest (SPEC §7.8).
 */
esp_err_t aktualino_crypto_sign_ed25519(const uint8_t *secret_key,
                                        size_t secret_key_len,
                                        const void *msg, size_t msg_len,
                                        uint8_t out_sig[64]);

/* Generate a fresh Ed25519 keypair (on-device ECU key, SPEC §6 step 4). */
esp_err_t aktualino_crypto_keygen_ed25519(uint8_t out_pub[32],
                                          uint8_t out_secret[64]);

#ifdef __cplusplus
}
#endif
