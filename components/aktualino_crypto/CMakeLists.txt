idf_component_register(
    SRCS
        "aktualino_crypto.c"   # esp_err_t wrapper
        "akt_canonical.c"      # portable canonical JSON (T1.1)
        "akt_crypto.c"         # portable verify/hash/sign (T1.2)
    INCLUDE_DIRS "include"
    # cJSON (json) is used in the PUBLIC header akt_crypto.h, so it must be a
    # public REQUIRES. mbedTLS (SHA-256 / RSASSA-PSS / base64) and libsodium
    # (Ed25519, via the espressif/libsodium managed component in idf_component.yml)
    # are implementation-only.
    REQUIRES esp_common json
    PRIV_REQUIRES mbedtls libsodium
)
