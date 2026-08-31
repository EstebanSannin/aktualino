idf_component_register(
    SRCS
        "aktualino_uptane.c"   # esp_err_t wrapper
        "akt_uptane.c"         # portable role verify / target select / manifest (T1.3, T1.4)
    INCLUDE_DIRS "include"
    # The public header akt_uptane.h includes cJSON.h (json) and akt_crypto.h
    # (aktualino_crypto), so both are public REQUIRES.
    REQUIRES esp_common json aktualino_crypto
)
