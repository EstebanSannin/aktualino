# Aktualino — ESP-IDF top-level project file.
#
# Build (via Docker on the build host, see README / tools/sync-build.sh):
#   idf.py -B build-esp32   set-target esp32   build
#   idf.py -B build-esp32s3 set-target esp32s3 build
#
# Components live under components/ (SPEC §5). main/ holds the app entry point.
cmake_minimum_required(VERSION 3.16)

# EXTRA_COMPONENT_DIRS is implicit (components/ is auto-discovered), listed here
# for clarity for anyone reading the tree.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components")

# App version -> esp_app_desc.version, used by the Phase-0 OTA "is-it-newer?"
# gate (T0.7). Override per build with the container env AKT_APP_VERSION
# (e.g. -e AKT_APP_VERSION=0.2.0); defaults to 0.1.0.
if(DEFINED ENV{AKT_APP_VERSION})
    set(PROJECT_VER "$ENV{AKT_APP_VERSION}")
else()
    set(PROJECT_VER "0.1.0")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(aktualino)
