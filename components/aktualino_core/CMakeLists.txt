idf_component_register(
    SRCS "aktualino_core.c"
    INCLUDE_DIRS "include"
    # Phase 2: the Director poll/verify loop drives the portable Uptane core
    # (aktualino_uptane/akt_crypto), the NVS store, and the mTLS net client.
    # json is public: aktualino_core.h exposes cJSON (verify_image_repo hands
    # back the verified image targets envelope for cross-repo matching).
    REQUIRES esp_common json aktualino_uptane aktualino_crypto
             aktualino_store aktualino_net aktualino_ota
)
