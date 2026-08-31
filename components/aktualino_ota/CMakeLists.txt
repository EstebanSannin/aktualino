idf_component_register(
    SRCS "aktualino_ota.c"
    INCLUDE_DIRS "include"
    # mbedtls is in REQUIRES (not PRIV_REQUIRES) because the public header
    # aktualino_ota.h exposes mbedtls_sha256_context in aktualino_ota_ctx_t.
    REQUIRES app_update esp_partition mbedtls
)
