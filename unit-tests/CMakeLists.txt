cmake_minimum_required(VERSION 3.14)  # FetchContent_MakeAvailable

if(${CMAKE_VERSION} VERSION_LESS 3.14)
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

# Speculos is used by the speculos-backed crypto tests as the pure-C
# implementation of the BOLOS syscalls, so we can link the real
# application crypto code against it instead of writing per-syscall mocks.
#
# By default the source tree is fetched from upstream at configure time,
# pinned to a known-good tag. To override (e.g. for offline builds or to
# test against a local speculos checkout), pass -DSPECULOS_SRC=<path>
# or set the SPECULOS_SRC environment variable.
#
# To skip the speculos-backed targets entirely, pass -DSPECULOS=OFF.
option(SPECULOS "Build the speculos-backed crypto tests" ON)
set(SPECULOS_GIT_TAG "v0.25.13" CACHE STRING
    "Tag/branch/commit of speculos to fetch when SPECULOS_SRC is not set.")

if(SPECULOS)
  if(NOT DEFINED SPECULOS_SRC AND DEFINED ENV{SPECULOS_SRC})
    set(SPECULOS_SRC $ENV{SPECULOS_SRC})
  endif()
  if(NOT SPECULOS_SRC)
    include(FetchContent)
    FetchContent_Declare(speculos
      GIT_REPOSITORY https://github.com/LedgerHQ/speculos.git
      GIT_TAG        ${SPECULOS_GIT_TAG}
      GIT_SHALLOW    TRUE
    )
    # Populate without running speculos's own CMakeLists.txt — that one
    # is configured for an ARM cross-compile and is not relevant here.
    # We only want the source tree.
    FetchContent_GetProperties(speculos)
    if(NOT speculos_POPULATED)
      FetchContent_Populate(speculos)
    endif()
    set(SPECULOS_SRC "${speculos_SOURCE_DIR}")
  endif()
endif()

add_compile_definitions(TEST DEBUG=0 PRINTF=printf COIN_NATIVE_SEGWIT_PREFIX=\"tb\")

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
add_executable(test_get_preimage test_get_preimage.c)
add_executable(test_extract_bip32_derivation test_extract_bip32_derivation.c)
add_executable(test_psbt_parse test_psbt_parse.c)
add_executable(test_check_merkle_tree_sorted test_check_merkle_tree_sorted.c)
add_executable(test_get_merkle_leaf_element test_get_merkle_leaf_element.c)
add_executable(test_get_merkle_preimage test_get_merkle_preimage.c)
add_executable(test_get_merkle_leaf_hash test_get_merkle_leaf_hash.c)
add_executable(test_get_merkle_leaf_index test_get_merkle_leaf_index.c)
add_executable(test_stream_preimage test_stream_preimage.c)
add_executable(test_stream_merkle_leaf_element test_stream_merkle_leaf_element.c)
add_executable(test_stream_merkleized_map_value test_stream_merkleized_map_value.c)
add_executable(test_get_merkleized_map test_get_merkleized_map.c)
add_executable(test_get_merkleized_map_value test_get_merkleized_map_value.c)

# Mock libraries
add_library(sha256 SHARED libs/sha-256.c)
add_library(cx_hash_mock SHARED libs/cx_hash_mock.c)
add_library(mock_dispatcher SHARED libs/mock_dispatcher.c)
add_library(psbt_parse SHARED libs/psbt_parse.c)
add_library(xpub SHARED libs/xpub.c)

# App's libraries
add_library(base58 SHARED $ENV{BOLOS_SDK}/lib_standard_app/base58.c)
add_library(bip32 SHARED $ENV{BOLOS_SDK}/lib_standard_app/bip32.c)
add_library(buffer SHARED $ENV{BOLOS_SDK}/lib_standard_app/buffer.c)
add_library(buffer_ext SHARED ../src/common/buffer_ext.c)
add_library(display_utils SHARED ../src/ui/display_utils.c)
add_library(extract_bip32_derivation SHARED ../src/handler/sign_psbt/extract_bip32_derivation.c)
add_library(get_merkle_leaf_hash SHARED ../src/handler/lib/get_merkle_leaf_hash.c)
add_library(get_merkle_leaf_element SHARED ../src/handler/lib/get_merkle_leaf_element.c)
add_library(get_merkle_preimage SHARED ../src/handler/lib/get_merkle_preimage.c)
add_library(get_preimage SHARED ../src/handler/lib/get_preimage.c)
add_library(check_merkle_tree_sorted SHARED ../src/handler/lib/check_merkle_tree_sorted.c)
add_library(get_merkle_leaf_index SHARED ../src/handler/lib/get_merkle_leaf_index.c)
add_library(merkle SHARED ../src/common/merkle.c)
add_library(stream_merkle_leaf_element SHARED ../src/handler/lib/stream_merkle_leaf_element.c)
add_library(stream_preimage SHARED ../src/handler/lib/stream_preimage.c)
add_library(stream_merkleized_map_value SHARED ../src/handler/lib/stream_merkleized_map_value.c)
add_library(get_merkleized_map SHARED ../src/handler/lib/get_merkleized_map.c)
add_library(get_merkleized_map_value SHARED ../src/handler/lib/get_merkleized_map_value.c)
add_library(parser SHARED ../src/common/parser_ext.c)
add_library(read SHARED $ENV{BOLOS_SDK}/lib_standard_app/read.c)
add_library(varint SHARED $ENV{BOLOS_SDK}/lib_standard_app/varint.c)
add_library(write SHARED $ENV{BOLOS_SDK}/lib_standard_app/write.c)

# Additional include directories for handler code
target_include_directories(extract_bip32_derivation PRIVATE ../src/handler ../src/handler/lib ../src/handler/sign_psbt ../src/common)
target_include_directories(get_merkle_leaf_hash PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(get_preimage PRIVATE ../src/handler ../src/handler/lib)
target_include_directories(mock_dispatcher PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(stream_merkle_leaf_element PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(stream_preimage PRIVATE ../src/handler ../src/handler/lib)
target_include_directories(stream_merkleized_map_value PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(get_merkleized_map PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(get_merkleized_map_value PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_extract_bip32_derivation PRIVATE ../src/handler ../src/handler/lib ../src/handler/sign_psbt ../src/common)
target_include_directories(get_merkle_leaf_element PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(get_merkle_preimage PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(check_merkle_tree_sorted PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(get_merkle_leaf_index PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_link_libraries(get_merkle_leaf_index PUBLIC get_merkle_leaf_hash)
target_include_directories(test_get_preimage PRIVATE ../src/handler ../src/handler/lib)
target_include_directories(test_get_merkle_preimage PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_get_merkle_leaf_element PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_check_merkle_tree_sorted PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_get_merkle_leaf_hash PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_get_merkle_leaf_index PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_stream_preimage PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_stream_merkle_leaf_element PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_stream_merkleized_map_value PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_get_merkleized_map PRIVATE ../src/handler ../src/handler/lib ../src/common)
target_include_directories(test_get_merkleized_map_value PRIVATE ../src/handler ../src/handler/lib ../src/common)

# Mock libraries
target_link_libraries(cx_hash_mock PUBLIC sha256)
target_link_libraries(mock_dispatcher PUBLIC psbt_parse)
target_link_libraries(xpub PUBLIC base58 sha256)

# App's libraries
target_link_libraries(test_bitvector PUBLIC cmocka gcov)
target_link_libraries(test_buffer PUBLIC cmocka gcov buffer buffer_ext varint read write bip32)
target_link_libraries(test_display_utils PUBLIC cmocka gcov display_utils)
target_link_libraries(test_parser PUBLIC cmocka gcov parser buffer buffer_ext varint read write bip32)
target_link_libraries(test_get_preimage PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle get_preimage)
target_link_libraries(test_get_merkle_preimage PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle get_merkle_preimage)
target_link_libraries(test_extract_bip32_derivation PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle extract_bip32_derivation stream_merkle_leaf_element get_merkle_leaf_hash stream_preimage psbt_parse)
target_link_libraries(test_psbt_parse PUBLIC cmocka gcov psbt_parse)
target_link_libraries(test_check_merkle_tree_sorted PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle check_merkle_tree_sorted get_merkle_leaf_element get_merkle_leaf_hash get_merkle_preimage stream_preimage psbt_parse)
target_link_libraries(test_get_merkle_leaf_element PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle get_merkle_leaf_element get_merkle_leaf_hash get_merkle_preimage stream_preimage psbt_parse)
target_link_libraries(test_get_merkle_leaf_hash PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle get_merkle_leaf_hash stream_preimage psbt_parse)
target_link_libraries(test_get_merkle_leaf_index PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle get_merkle_leaf_hash get_merkle_leaf_index stream_preimage psbt_parse)
target_link_libraries(test_stream_preimage PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle stream_preimage psbt_parse)
target_link_libraries(test_stream_merkle_leaf_element PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle stream_merkle_leaf_element get_merkle_leaf_hash stream_preimage psbt_parse)
target_link_libraries(test_stream_merkleized_map_value PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle stream_merkleized_map_value stream_merkle_leaf_element get_merkle_leaf_hash get_merkle_leaf_index stream_preimage psbt_parse)
target_link_libraries(test_get_merkleized_map PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle get_merkleized_map check_merkle_tree_sorted get_merkle_leaf_element get_merkle_leaf_hash get_merkle_preimage stream_preimage psbt_parse)
target_link_libraries(test_get_merkleized_map_value PUBLIC cmocka gcov mock_dispatcher cx_hash_mock sha256 buffer buffer_ext varint read write bip32 merkle get_merkleized_map_value get_merkle_leaf_element get_merkle_leaf_hash get_merkle_leaf_index get_merkle_preimage stream_preimage psbt_parse)

add_test(test_bitvector test_bitvector)
add_test(test_buffer test_buffer)
add_test(test_display_utils test_display_utils)
add_test(test_parser test_parser)
add_test(test_get_preimage test_get_preimage)
add_test(test_extract_bip32_derivation test_extract_bip32_derivation)
add_test(test_psbt_parse test_psbt_parse)
add_test(test_check_merkle_tree_sorted test_check_merkle_tree_sorted)
add_test(test_get_merkle_leaf_element test_get_merkle_leaf_element)
add_test(test_get_merkle_preimage test_get_merkle_preimage)
add_test(test_get_merkle_leaf_hash test_get_merkle_leaf_hash)
add_test(test_get_merkle_leaf_index test_get_merkle_leaf_index)
add_test(test_stream_preimage test_stream_preimage)
add_test(test_stream_merkle_leaf_element test_stream_merkle_leaf_element)
add_test(test_stream_merkleized_map_value test_stream_merkleized_map_value)
add_test(test_get_merkleized_map test_get_merkleized_map)
add_test(test_get_merkleized_map_value test_get_merkleized_map_value)

# ---------------------------------------------------------------------------
# Speculos-backed crypto tests
# ---------------------------------------------------------------------------
# test_crypto exercises the real app crypto code (src/crypto.c) by
# linking against the C implementation of the BOLOS syscalls provided by
# speculos. Enabled by default (see the SPECULOS option above). Requires
# OpenSSL development headers on the host (libssl-dev on Debian/Ubuntu).

if(SPECULOS AND SPECULOS_SRC)
  find_package(OpenSSL REQUIRED)

  message(STATUS "Building speculos-backed crypto tests from ${SPECULOS_SRC}")

  set(SPECULOS_BOLOS_SOURCES
    ${SPECULOS_SRC}/src/bolos/cx_bn.c
    ${SPECULOS_SRC}/src/bolos/cx_blake2b.c
    ${SPECULOS_SRC}/src/bolos/cx_curve25519.c
    ${SPECULOS_SRC}/src/bolos/cx_ec.c
    ${SPECULOS_SRC}/src/bolos/cx_ec_domain.c
    ${SPECULOS_SRC}/src/bolos/cx_ecpoint.c
    ${SPECULOS_SRC}/src/bolos/cx_ed25519.c
    ${SPECULOS_SRC}/src/bolos/cx_hash.c
    ${SPECULOS_SRC}/src/bolos/cx_hmac.c
    ${SPECULOS_SRC}/src/bolos/cx_math.c
    ${SPECULOS_SRC}/src/bolos/cx_montgomery.c
    ${SPECULOS_SRC}/src/bolos/cx_mpi.c
    ${SPECULOS_SRC}/src/bolos/cx_ripemd160.c
    ${SPECULOS_SRC}/src/bolos/cx_rng_rfc6979.c
    ${SPECULOS_SRC}/src/bolos/cx_scc.c
    ${SPECULOS_SRC}/src/bolos/cx_sha256.c
    ${SPECULOS_SRC}/src/bolos/cx_sha3.c
    ${SPECULOS_SRC}/src/bolos/cx_sha512.c
    ${SPECULOS_SRC}/src/bolos/cx_twisted_edwards.c
    ${SPECULOS_SRC}/src/bolos/cx_utils.c
    ${SPECULOS_SRC}/src/bolos/cx_weierstrass.c
    ${SPECULOS_SRC}/src/bolos/cxlib.c
    ${SPECULOS_SRC}/src/bolos/os_bip32.c
  )

  add_library(speculos_bolos STATIC ${SPECULOS_BOLOS_SOURCES})
  target_compile_options(speculos_bolos PRIVATE
    -w  # speculos sources emit warnings that are not our concern
  )
  target_compile_definitions(speculos_bolos PRIVATE
    OS_LITTLE_ENDIAN NATIVE_64BITS HAVE_BOLOS=1
  )
  # BEFORE: speculos ships its own appflags.h (with `extern app_flags`)
  # that must shadow the Ledger SDK's stripped-down appflags.h added
  # at global scope above.
  target_include_directories(speculos_bolos BEFORE PRIVATE
    ${SPECULOS_SRC}/sdk
    ${SPECULOS_SRC}/src
    ${SPECULOS_SRC}/src/bolos
    ${SPECULOS_SRC}/src/bolos/io/sdk/include
  )
  target_link_libraries(speculos_bolos PUBLIC OpenSSL::Crypto)

  add_library(speculos_bridge STATIC libs/speculos_bridge.c)
  target_compile_definitions(speculos_bridge PRIVATE HAVE_BOLOS=1)
  target_include_directories(speculos_bridge BEFORE PRIVATE
    ${SPECULOS_SRC}/sdk
    ${SPECULOS_SRC}/src
    ${SPECULOS_SRC}/src/bolos
  )
  target_link_libraries(speculos_bridge PUBLIC speculos_bolos OpenSSL::Crypto)

  # Build the application code against the real SDK headers (not the
  # per-test mock_includes) so it sees the same syscall signatures the
  # speculos bridge implements. crypto.c can now be compiled this way,
  # which removes the need to mock it for tests that depend on it.
  add_library(app_crypto STATIC
    ../src/crypto.c
    ../src/secp256k1.c
    ../src/common/wallet.c
    ../src/common/script.c
    ../src/common/segwit_addr.c
  )
  target_compile_options(app_crypto PRIVATE -fno-stack-protector)
  target_compile_definitions(app_crypto PRIVATE
    HAVE_HASH HAVE_RIPEMD160 HAVE_SHA256 HAVE_SHA512 HAVE_HMAC HAVE_MATH
    HAVE_ECC HAVE_ECC_WEIERSTRASS HAVE_SECP256K1_CURVE HAVE_ECDSA
    API_LEVEL=22 OS_IO_SEPH_BUFFER_SIZE=272 IO_USB_MAX_ENDPOINTS=6
    BIP32_PUBKEY_VERSION=0x043587CF BIP44_COIN_TYPE=1
    COIN_P2PKH_VERSION=111 COIN_P2SH_VERSION=196
    COIN_COINID_SHORT=\"TEST\"
  )
  # BEFORE: SDK headers take precedence over the mock_includes added at
  # global scope above. The whole point of this target is to compile
  # the app code against the REAL SDK declarations.
  target_include_directories(app_crypto BEFORE PRIVATE
    ../src
    ../src/common
    ../src/debug-helpers
    ../src/boilerplate
    $ENV{BOLOS_SDK}/target/nanox/include
    $ENV{BOLOS_SDK}/include
    $ENV{BOLOS_SDK}/io/include
    $ENV{BOLOS_SDK}/io_legacy/include
    $ENV{BOLOS_SDK}/protocol/include
    $ENV{BOLOS_SDK}/lib_standard_app
    $ENV{BOLOS_SDK}/lib_cxng/include
    $ENV{BOLOS_SDK}/lib_cxng/src
    $ENV{BOLOS_SDK}/lib_stusb/include
  )
  # Anything linking app_crypto needs the speculos syscall bridge and the
  # SDK helpers the app code calls into. Expose them as PUBLIC so each
  # test only has to mention app_crypto plus its own extras.
  target_link_libraries(app_crypto PUBLIC
    speculos_bridge
    base58 bip32 read write varint
  )

  add_executable(test_crypto test_crypto.c)
  target_link_libraries(test_crypto PRIVATE cmocka gcov app_crypto xpub)
  add_test(test_crypto test_crypto)

  add_executable(test_script test_script.c)
  target_link_libraries(test_script PRIVATE cmocka gcov app_crypto)
  add_test(test_script test_script)

  add_executable(test_wallet test_wallet.c)
  target_link_libraries(test_wallet PRIVATE cmocka gcov app_crypto buffer buffer_ext)
  add_test(test_wallet test_wallet)
endif()
