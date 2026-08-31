idf_component_register(
    SRCS "aktualino_time.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_common
    PRIV_REQUIRES lwip
)
