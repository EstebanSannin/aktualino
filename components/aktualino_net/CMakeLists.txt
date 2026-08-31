idf_component_register(
    SRCS "aktualino_net.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_client
    PRIV_REQUIRES esp-tls mbedtls
)
