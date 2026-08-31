# aktualino_script — the Berry script secondary (install + run + report).
#
# Gated on CONFIG_AKTUALINO_SCRIPT_SECONDARY, but NOT via the
# `if(NOT CONFIG) idf_component_register() return()` empty-component trick: that
# breaks IDF's requirement-expansion pass (CONFIG_* is not set there, so the
# empty register captures no PRIV_REQUIRES and the real build can't find their
# headers). Instead we always register with the requires and guard the SOURCE
# internally (#if CONFIG_AKTUALINO_SCRIPT_SECONDARY wraps all of aktualino_script.c),
# so a feature-off build compiles an empty translation unit -> ~0 KB, nothing links.
idf_component_register(
    SRCS "aktualino_script.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES
        aktualino_core
        aktualino_net
        aktualino_store
        aktualino_prov
        aktualino_uptane
        aktualino_berry
        mbedtls
        esp_partition
        spi_flash
)
