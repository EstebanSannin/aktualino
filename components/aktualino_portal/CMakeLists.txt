idf_component_register(
    SRCS "aktualino_portal.c"
    INCLUDE_DIRS "include"
    # SoftAP + STA Wi-Fi, captive DNS (lwip sockets), HTTP server, MAC.
    REQUIRES esp_wifi esp_netif esp_event esp_http_server
    # NVS creds (aktualino_store), cJSON (json), factory MAC (esp_hw_support),
    # lwip for the raw UDP DNS socket.
    PRIV_REQUIRES nvs_flash lwip json esp_hw_support aktualino_store
)

# Embed the setup page gzipped: gzip www/portal.html at build time, then link it
# in as _binary_portal_html_gz_start/_end. -n drops the name+timestamp so the
# bytes are reproducible. The page uses system fonts + inline CSS/JS (the setup
# AP has no internet), so the compressed blob is fully self-contained.
set(_portal_src "${CMAKE_CURRENT_SOURCE_DIR}/www/portal.html")
set(_portal_gz  "${CMAKE_CURRENT_BINARY_DIR}/portal.html.gz")
add_custom_command(
    OUTPUT "${_portal_gz}"
    COMMAND gzip -9 -n -c "${_portal_src}" > "${_portal_gz}"
    DEPENDS "${_portal_src}"
    COMMENT "gzip aktualino setup portal page"
    VERBATIM)
add_custom_target(aktualino_portal_html DEPENDS "${_portal_gz}")
add_dependencies(${COMPONENT_LIB} aktualino_portal_html)
target_add_binary_data(${COMPONENT_LIB} "${_portal_gz}" BINARY)
