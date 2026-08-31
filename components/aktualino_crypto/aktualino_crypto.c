/*
 * aktualino_crypto.c — ESP component wrapper (esp_err_t surface) over the
 * portable akt_crypto core (akt_crypto.h). All real logic lives in the portable
 * core so it is host-unit-tested; this file just adapts return types for the
 * on-target callers (SPEC §5, §8).
 */
#include "aktualino_crypto.h"
#include "akt_crypto.h"

static const char *method_str(aktualino_sig_method_t m)
{
    switch (m) {
        case AKT_SIG_ED25519:           return "ed25519";
        case AKT_SIG_RSASSA_PSS_SHA256: return "rsassa-pss-sha256";
        default:                        return "unknown";
    }
}

aktualino_sig_method_t aktualino_crypto_method_from_str(const char *method)
{
    switch (akt_method_from_str(method)) {
        case AKT_METHOD_ED25519:           return AKT_SIG_ED25519;
        case AKT_METHOD_RSASSA_PSS_SHA256: return AKT_SIG_RSASSA_PSS_SHA256;
        default:                           return AKT_SIG_UNKNOWN;
    }
}

esp_err_t aktualino_crypto_sha256(const void *data, size_t len, uint8_t out32[32])
{
    return akt_sha256(data, len, out32) == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t aktualino_crypto_verify(aktualino_sig_method_t method,
                                  const uint8_t *pubkey, size_t pubkey_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const void *msg, size_t msg_len)
{
    bool ok = akt_verify(method_str(method), pubkey, pubkey_len,
                         msg, msg_len, sig, sig_len);
    return ok ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t aktualino_crypto_sign_ed25519(const uint8_t *secret_key,
                                        size_t secret_key_len,
                                        const void *msg, size_t msg_len,
                                        uint8_t out_sig[64])
{
    if (secret_key_len != 64) return ESP_ERR_INVALID_ARG;
    return akt_sign_ed25519(secret_key, msg, msg_len, out_sig) == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t aktualino_crypto_keygen_ed25519(uint8_t out_pub[32], uint8_t out_secret[64])
{
    return akt_keygen_ed25519(out_pub, out_secret) == 0 ? ESP_OK : ESP_FAIL;
}
