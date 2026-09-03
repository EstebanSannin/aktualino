idf_component_register(
    SRCS
        "aktualino_main.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        # Core IDF services used by the Phase-0 app entry.
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        lwip
        esp_app_format
        app_update
        # Streaming HTTPS OTA against the dumb server (T0.7).
        esp_https_ota
        esp_http_client
        esp-tls
        # Aktualino components wired into the boot flow.
        aktualino_core
        aktualino_time
        aktualino_ota
        aktualino_net
        # Phase 1: provisioning + credential store.
        aktualino_prov
        aktualino_store
        # Item ③: SoftAP captive-portal provisioning.
        aktualino_portal
        # GPIO for the factory-reset-to-AP hook (BOOT/GPIO0).
        driver
        # Optional Berry script secondary (empty components unless the Kconfig
        # switch is on, so these REQUIRES are harmless when the feature is off).
        aktualino_berry
        aktualino_script
    EMBED_TXTFILES
        # Phase 2: the Director root.json TRUST ANCHOR (public Uptane metadata,
        # TOFU-free — the device verifies fetched roots against this and walks the
        # rotation chain forward). Committed (not a secret). Symbols:
        # _binary_director_root_json_start / _end.
        "embed/director_root.json"
        # Phase 4a: the IMAGE-repo root.json TRUST ANCHOR (public Uptane metadata,
        # /repo user_repo root — a SECOND, independent anchor with its own keys).
        # Committed (not a secret). Symbols:
        # _binary_image_root_json_start / _end.
        "embed/image_root.json"
)

# Build-time rollback demo (WORKPLAN T0.9 Stage C.2): when the container passes
# AKT_ROLLBACK_TEST=1, the app refuses to confirm a freshly-OTA'd image so the
# bootloader rolls it back. Off by default.
if(DEFINED ENV{AKT_ROLLBACK_TEST})
    target_compile_definitions(${COMPONENT_LIB} PRIVATE AKTUALINO_ROLLBACK_TEST=1)
endif()

# Item ③ bench test (AKT_PORTAL_TEST=1): force SoftAP portal mode even when
# Wi-Fi is baked, and also join that baked Wi-Fi as STA so the portal is
# reachable from the wired LAN for curl-driven endpoint + provision tests
# (a wired build host cannot associate to the ESP's AP). Off by default; never for release.
if(DEFINED ENV{AKT_PORTAL_TEST})
    target_compile_definitions(${COMPONENT_LIB} PRIVATE AKTUALINO_PORTAL_TEST_STA=1)
endif()
