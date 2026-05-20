include_guard()
cmake_minimum_required(VERSION 3.14)

if(${CMAKE_VERSION} VERSION_LESS 3.14)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

project(
  BitcoinFuzzer
  VERSION 1.0
  DESCRIPTION "App Bitcoin Fuzzer"
  LANGUAGES C)

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined, CMake will exit.")
  return()
endif()

include(${BOLOS_SDK}/fuzzing/cmake/LedgerAppFuzz.cmake)
ledger_fuzz_setup()

set(APP_SOURCE_DIR ${CMAKE_SOURCE_DIR}/..)
file(GLOB_RECURSE C_SOURCES "${CMAKE_SOURCE_DIR}/mock/*.c" "${APP_SOURCE_DIR}/src/*.c")
list(FILTER C_SOURCES EXCLUDE REGEX ".*/debug-helpers/.*")
list(REMOVE_ITEM C_SOURCES "${APP_SOURCE_DIR}/src/app_main.c")
set(COVERAGE_SIGUSR1_SOURCE "${CMAKE_SOURCE_DIR}/mock/coverage_sigusr1.c")
list(REMOVE_ITEM C_SOURCES "${COVERAGE_SIGUSR1_SOURCE}")

# Match the production Makefile, which force-includes debug-helpers/debug.h
# on every app translation unit. That header pulls the SDK's os.h (and
# transitively stdbool.h/stdint.h), so app headers relying on `bool` or
# `size_t` without explicit <stdbool.h>/<stddef.h> still compile under
# fuzzing. Scope this to the app + mock sources only — the Absolution-
# generated fuzzer.c must stay on its minimal include set to avoid
# redefining SDK-typed externs such as `io_seph_app_t G_io_app`.
set_source_files_properties(
    ${C_SOURCES}
    PROPERTIES
        COMPILE_OPTIONS "-include;${APP_SOURCE_DIR}/src/debug-helpers/debug.h"
)

# Collect every subdirectory that contains a header, so includes like
# "sign_psbt_cache.h" or "get_merkle_leaf_element.h" resolve without
# having to track the app's internal layout here.
file(GLOB_RECURSE APP_HEADERS "${APP_SOURCE_DIR}/src/*.h")
set(APP_INCLUDE_DIRS "")
foreach(header ${APP_HEADERS})
    get_filename_component(header_dir ${header} DIRECTORY)
    list(APPEND APP_INCLUDE_DIRS ${header_dir})
endforeach()
list(REMOVE_DUPLICATES APP_INCLUDE_DIRS)

set(_fuzz_compile_defs HAVE_AUTOAPPROVE_FOR_PERF_TESTS=1)
message(STATUS "Bitcoin fuzz build: single structured harness")

set(_fuzz_extra_sources "")
if(FUZZ_ENABLE_SOURCE_COVERAGE AND EXISTS "${COVERAGE_SIGUSR1_SOURCE}")
    list(APPEND _fuzz_extra_sources "${COVERAGE_SIGUSR1_SOURCE}")
    message(STATUS "Bitcoin fuzz build: SIGUSR1 coverage dump hook enabled")
endif()

ledger_fuzz_add_app_target(
    NAME fuzz_app
    INVARIANT ${CMAKE_SOURCE_DIR}/invariants/fuzz_globals.zon
    SOURCES
        ${C_SOURCES}
        ${_fuzz_extra_sources}
    INCLUDE_DIRECTORIES
        ${APP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/mock/
        ${CMAKE_SOURCE_DIR}
    COMPILE_DEFINITIONS
        ${_fuzz_compile_defs}
)
