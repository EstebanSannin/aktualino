#
# Host unit tests for the portable Uptane verification core (WORKPLAN T1.1–T1.4).
#
# Runs OFF-TARGET in a throwaway container with the host toolchain + libsodium +
# mbedTLS + libcjson + openssl + python3 (see the runner in WORKPLAN "Environment").
# It compiles the SAME portable .c files that the ESP components build on-target,
# proving the security logic without hardware.
#
cmake_minimum_required(VERSION 3.16)
project(aktualino_host_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wno-unused-parameter -O1 -g)

set(REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Portable core — identical sources to the on-target components.
set(CORE_SRCS
    ${REPO_ROOT}/components/aktualino_crypto/akt_canonical.c
    ${REPO_ROOT}/components/aktualino_crypto/akt_crypto.c
    ${REPO_ROOT}/components/aktualino_uptane/akt_uptane.c
)

set(CORE_INCLUDES
    ${REPO_ROOT}/components/aktualino_crypto/include
    ${REPO_ROOT}/components/aktualino_uptane/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    /usr/include/cjson            # Debian libcjson-dev header location
)

# Locate host libraries.
find_library(SODIUM_LIB     sodium      REQUIRED)
find_library(CJSON_LIB      cjson       REQUIRED)
find_library(MBEDTLS_LIB    mbedtls     REQUIRED)
find_library(MBEDX509_LIB   mbedx509    REQUIRED)
find_library(MBEDCRYPTO_LIB mbedcrypto  REQUIRED)

set(CORE_LIBS
    ${SODIUM_LIB} ${CJSON_LIB}
    ${MBEDTLS_LIB} ${MBEDX509_LIB} ${MBEDCRYPTO_LIB} m
)

# Regenerate the fixture header from gen.py (mints an ed25519 key via openssl,
# emits root/targets fixtures signed over canonical(signed), + canon cross-check).
set(GEN_HEADER ${CMAKE_CURRENT_BINARY_DIR}/generated_fixtures.h)
add_custom_command(
    OUTPUT  ${GEN_HEADER}
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/gen.py ${GEN_HEADER}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/gen.py
    COMMENT "Generating Uptane fixtures (gen.py)"
    VERBATIM
)
add_custom_target(gen_fixtures DEPENDS ${GEN_HEADER})

# Emit the synthetic Torizon-shaped RSA metadata header from the committed
# fixtures under fixtures/torizon/ (pure serialization; no crypto at build time).
set(TZ_HEADER ${CMAKE_CURRENT_BINARY_DIR}/synthetic_torizon_metadata.h)
file(GLOB TZ_FIXTURES ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/torizon/*.json)
add_custom_command(
    OUTPUT  ${TZ_HEADER}
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/gen_torizon.py ${TZ_HEADER}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/gen_torizon.py ${TZ_FIXTURES}
    COMMENT "Generating synthetic Torizon fixtures (gen_torizon.py)"
    VERBATIM
)
add_custom_target(gen_torizon_fixtures DEPENDS ${TZ_HEADER})

enable_testing()

function(akt_add_test name src)
    add_executable(${name} ${src} ${CORE_SRCS})
    add_dependencies(${name} gen_fixtures)
    target_include_directories(${name} PRIVATE ${CORE_INCLUDES})
    target_link_libraries(${name} PRIVATE ${CORE_LIBS})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

akt_add_test(test_canonical test_canonical.c)
akt_add_test(test_verify    test_verify.c)
akt_add_test(test_role      test_role.c)
akt_add_test(test_manifest  test_manifest.c)
# Phase-3: live-Director target selection (ecuIdentifiers), correlation-id
# extraction, and the installation_report manifest builder.
akt_add_test(test_phase3    test_phase3.c)
# Phase-4a: Image-repo meta-hash chain (over raw served bytes) + cross-repo
# target matching (the Uptane two-repo guarantee), exercised against the
# synthetic Torizon-shaped RSA image repo: roles signature-verify against the
# image root and the chain is checked over those exact served bytes.
add_executable(test_tworepo test_tworepo.c ${CORE_SRCS})
add_dependencies(test_tworepo gen_torizon_fixtures)
target_include_directories(test_tworepo PRIVATE ${CORE_INCLUDES})
target_link_libraries(test_tworepo PRIVATE ${CORE_LIBS})
add_test(NAME test_tworepo COMMAND test_tworepo)

# Torizon Cloud RSA path: run the SAME portable core against synthetic,
# Torizon-Cloud-shaped metadata signed with RSASSA-PSS-SHA256 / RSA-2048.
# Proves canonical-JSON + RSA-PSS verify + the Image-repo meta-hash chain.
add_executable(test_torizon_metadata test_torizon_metadata.c ${CORE_SRCS})
add_dependencies(test_torizon_metadata gen_torizon_fixtures)
target_include_directories(test_torizon_metadata PRIVATE ${CORE_INCLUDES})
target_link_libraries(test_torizon_metadata PRIVATE ${CORE_LIBS})
add_test(NAME test_torizon_metadata COMMAND test_torizon_metadata)
