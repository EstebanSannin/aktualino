idf_component_register(
    SRCS "aktualino_store.c"
    INCLUDE_DIRS "include"
    # Phase-1 (T1.5) will use nvs_flash for the credential/metadata store.
    REQUIRES esp_common
    PRIV_REQUIRES nvs_flash
)
