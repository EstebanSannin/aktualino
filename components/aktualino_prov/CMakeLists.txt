idf_component_register(
    SRCS "aktualino_prov.c"
    INCLUDE_DIRS "include"
    # T1.5: aktualino_net (mTLS POST/PUT), aktualino_store (persist creds),
    # aktualino_crypto (ECU keygen), aktualino_uptane (first manifest).
    REQUIRES esp_common aktualino_net aktualino_store aktualino_crypto aktualino_uptane
    # cJSON (json), MAC (esp_hw_support), running-app desc (esp_app_format),
    # running partition (app_update / spi_flash).
    # esp_rom: ROM miniz (tinfl) to inflate the Torizon device.zip on-device (A2).
    PRIV_REQUIRES json esp_hw_support esp_app_format app_update esp_partition esp_rom
)
