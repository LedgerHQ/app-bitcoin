cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
  VERSION 0.1
  DESCRIPTION "Unit tests for Ledger Nano application"
  LANGUAGES C)

# guard against bad build-type strings
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

if(NOT DEFINED ENV{BOLOS_SDK})
    message(FATAL_ERROR "BOLOS_SDK is not defined.")
endif()

add_compile_definitions(TEST DEBUG=0 SKIP_FOR_CMOCKA PRINTF=printf COIN_NATIVE_SEGWIT_PREFIX=\"tb\")

include_directories(../src)
include_directories(../src/debug-helpers)
include_directories(../src/boilerplate)
include_directories(mock_includes)
include_directories(libs)
include_directories($ENV{BOLOS_SDK})
include_directories($ENV{BOLOS_SDK}/include)
include_directories($ENV{BOLOS_SDK}/lib_standard_app)

add_executable(test_bitvector test_bitvector.c)
add_executable(test_buffer test_buffer.c)
add_executable(test_display_utils test_display_utils.c)
add_executable(test_parser test_parser.c)
add_executable(test_script test_script.c)
add_executable(test_wallet test_wallet.c)
add_executable(test_get_preimage test_get_preimage.c)

# add_executable(test_crypto test_crypto.c)

# Mock libraries
add_library(crypto_mocks SHARED libs/crypto_mocks.c)
add_library(sha256 SHARED libs/sha-256.c)
add_library(cx_hash_mock SHARED libs/cx_hash_mock.c)
add_library(mock_dispatcher SHARED libs/mock_dispatcher.c)

# App's libraries
add_library(base58 SHARED $ENV{BOLOS_SDK}/lib_standard_app/base58.c)
add_library(bip32 SHARED $ENV{BOLOS_SDK}/lib_standard_app/bip32.c)
add_library(buffer SHARED $ENV{BOLOS_SDK}/lib_standard_app/buffer.c)
add_library(buffer_ext SHARED ../src/common/buffer_ext.c)
add_library(display_utils SHARED ../src/ui/display_utils.c)
add_library(get_preimage SHARED ../src/handler/lib/get_preimage.c)
add_library(merkle SHARED ../src/common/merkle.c)
add_library(parser SHARED ../src/common/parser_ext.c)
add_library(read SHARED $ENV{BOLOS_SDK}/lib_standard_app/read.c)
add_library(script SHARED ../src/common/script.c)
add_library(varint SHARED $ENV{BOLOS_SDK}/lib_standard_app/varint.c)
add_library(wallet SHARED ../src/common/wallet.c)
add_library(write SHARED $ENV{BOLOS_SDK}/lib_standard_app/write.c)

# add_library(crypto SHARED ../src/crypto.c)

# Additional include directories for handler code
target_include_directories(get_preimage PRIVATE ../src/handler ../src/handler/lib)
target_include_directories(mock_dispatcher PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_get_preimage PRIVATE ../src/handler ../src/handler/lib)

# Mock libraries
target_link_libraries(crypto_mocks PUBLIC sha256)
target_link_libraries(cx_hash_mock PUBLIC sha256)

# App's libraries
target_link_libraries(test_bitvector PUBLIC cmocka gcov)
target_link_libraries(test_buffer PUBLIC cmocka gcov buffer buffer_ext varint read write bip32)
target_link_libraries(test_display_utils PUBLIC cmocka gcov display_utils)
target_link_libraries(test_parser PUBLIC cmocka gcov parser buffer buffer_ext varint read write bip32)
target_link_libraries(test_script PUBLIC cmocka gcov script buffer varint read write bip32)
target_link_libraries(test_wallet PUBLIC cmocka gcov wallet script buffer buffer_ext varint read write bip32 base58 crypto_mocks)
target_link_libraries(test_get_preimage PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle get_preimage)

# target_link_libraries(test_crypto PUBLIC cmocka gcov crypto)
add_test(test_bitvector test_bitvector)
add_test(test_buffer test_buffer)
add_test(test_display_utils test_display_utils)
add_test(test_parser test_parser)
add_test(test_script test_script)
add_test(test_wallet test_wallet)
add_test(test_get_preimage test_get_preimage)

# add_test(test_crypto test_crypto)
