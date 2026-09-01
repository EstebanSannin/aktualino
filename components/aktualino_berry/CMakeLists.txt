# aktualino_berry — vendored Berry VM (berry/) + the embedding wrapper.
#
# Gated on CONFIG_AKTUALINO_SCRIPT_SECONDARY (docs/berry-secondary-spec.md §1.1):
# when the feature is OFF, register an EMPTY component so nothing is compiled or
# linked (~0 KB) while dependents can still resolve the component name.
if(NOT CONFIG_AKTUALINO_SCRIPT_SECONDARY)
    idf_component_register()
    return()
endif()

set(BERRY_DIR  "${CMAKE_CURRENT_LIST_DIR}/berry")
set(BERRY_CONF "${CMAKE_CURRENT_LIST_DIR}/conf/berry_conf.h")
set(BERRY_GEN  "${BERRY_DIR}/generate")

file(GLOB BERRY_SRCS "${BERRY_DIR}/src/*.c")
set(BERRY_PORT_SRCS
    "${BERRY_DIR}/default/be_modtab.c"
    "${BERRY_DIR}/default/be_port.c")

idf_component_register(
    SRCS
        "aktualino_berry.c"           # the embedding wrapper
        ${BERRY_SRCS}                 # the Berry VM
        ${BERRY_PORT_SRCS}            # module table + platform port
    INCLUDE_DIRS
        "include"                     # aktualino_berry.h (public)
        "conf"                        # our berry_conf.h — shadows the vendored
                                      # default (berry/default is NOT on the path)
        "berry/src"                   # berry.h + be_*.h (public: our header pulls berry.h)
)

# Berry keeps its built-in constants in a generated const-string table. coc
# (python3) scans the sources + config and emits headers that the Berry .c files
# #include "../generate/..." with a LITERAL relative path — so the output must
# land in berry/generate/ (adjacent to src/). This is the same
# codegen-as-build-step pattern as test/CMakeLists.txt. berry/generate/ is
# gitignored (build output). coc reads the SAME config file the compiler uses
# (conf/berry_conf.h) — it is a text macro-scanner and cannot follow #include.
add_custom_command(
    OUTPUT  "${BERRY_GEN}/be_const_strtab.h"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${BERRY_GEN}"
    COMMAND python3 "${BERRY_DIR}/tools/coc/coc" -o "${BERRY_GEN}"
            "${BERRY_DIR}/src" "${BERRY_DIR}/default" -c "${BERRY_CONF}"
    DEPENDS ${BERRY_SRCS} ${BERRY_PORT_SRCS} "${BERRY_CONF}"
    COMMENT "Berry: coc codegen (const-string table)"
    VERBATIM)
add_custom_target(aktualino_berry_coc DEPENDS "${BERRY_GEN}/be_const_strtab.h")
add_dependencies(${COMPONENT_LIB} aktualino_berry_coc)

# The vendored Berry sources are third-party C99; don't hold them to our own
# warning bar (keeps -Werror builds of Aktualino code clean).
set_source_files_properties(${BERRY_SRCS} ${BERRY_PORT_SRCS}
    PROPERTIES COMPILE_OPTIONS "-w")
