cmake_minimum_required(VERSION 3.20)

project(
  BitcoinFuzzer
  VERSION 1.0
  DESCRIPTION "App Bitcoin Fuzzer"
  LANGUAGES C)

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined, CMake will exit.")
endif()

# Consumed by ledger_fuzz_setup() below, so it must be set first.
set(LEDGER_FUZZ_APP_UBSAN_IGNORELIST
    "${CMAKE_SOURCE_DIR}/sanitizers/ubsan-ignorelist.txt")

include(${BOLOS_SDK}/fuzzing/cmake/LedgerAppFuzz.cmake)
ledger_fuzz_setup()

set(APP_SOURCE_DIR ${CMAKE_SOURCE_DIR}/..)
file(GLOB_RECURSE C_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/mock/*.c" "${APP_SOURCE_DIR}/src/*.c")

# The client-command host is the app's own unit-test mock_dispatcher, not a second
# implementation: same four commands, same Merkle code (src/common/merkle.c), same
# SHA-256 (cx_hash_sha256).
list(APPEND C_SOURCES "${APP_SOURCE_DIR}/unit-tests/libs/mock_dispatcher.c")
# mock_dispatcher_add_psbt() calls psbt_parse(); the fuzz harness never uses that
# entry point, but it lives in the same translation unit so the symbol is required.
list(APPEND C_SOURCES "${APP_SOURCE_DIR}/unit-tests/libs/psbt_parse.c")
list(FILTER C_SOURCES EXCLUDE REGEX ".*/debug-helpers/.*")

# Force-include debug-helpers/debug.h on app + mock sources (matching the
# production Makefile) so app headers relying on bool/size_t compile. Scoped
# to these sources only — the generated fuzzer.c keeps its minimal includes.
# The -fsanitize=function carve-out for the generic callback typedefs lives in
# sanitizers/ubsan-ignorelist.txt, scoped to the files that own the idiom.
set_source_files_properties(
    ${C_SOURCES}
    PROPERTIES
        COMPILE_OPTIONS "-include;${APP_SOURCE_DIR}/src/debug-helpers/debug.h"
)

# Add every directory containing a header so app-internal includes resolve
# without tracking the source layout here.
ledger_fuzz_collect_include_dirs(APP_INCLUDE_DIRS ${APP_SOURCE_DIR}/src)

# Enable the app's UI auto-approve (display.c) so the harness never blocks on confirmations.
set(_fuzz_compile_defs HAVE_AUTOAPPROVE_FOR_PERF_TESTS=1)
message(STATUS "Bitcoin fuzz build: single structured harness")

ledger_fuzz_add_app_target(
    NAME fuzz_app
    INVARIANT ${CMAKE_SOURCE_DIR}/invariants/fuzz_globals.zon
    SOURCES
        ${C_SOURCES}
    INCLUDE_DIRECTORIES
        ${APP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/mock/
        ${APP_SOURCE_DIR}/unit-tests/libs/
        ${CMAKE_SOURCE_DIR}
    COMPILE_DEFINITIONS
        ${_fuzz_compile_defs}
)
