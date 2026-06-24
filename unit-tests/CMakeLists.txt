cmake_minimum_required(VERSION 3.14)

project(unit_tests
  VERSION 0.1
  DESCRIPTION "Unit tests for Ledger Nano application"
  LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
enable_testing()

# Emit build/compile_commands.json so editor tooling (clangd, VSCode's
# C/C++ extension, ...) can pick up the exact compile flags / include
# paths used for each source file. Without this, files like
# libs/speculos_bridge.c — which depend on per-target BEFORE PRIVATE
# include directories — show spurious "missing header" errors.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

# --coverage on the link line already pulls in libgcov.
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --coverage")
set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS} --coverage")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt.")
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
include_directories(libs)
include_directories($ENV{BOLOS_SDK})
include_directories($ENV{BOLOS_SDK}/include)
include_directories($ENV{BOLOS_SDK}/lib_standard_app)
include_directories($ENV{BOLOS_SDK}/target/nanos2/include)

# Include paths shared by every target under ../src/handler.
set(HANDLER_INCLUDES ../src/handler ../src/handler/lib ../src/common)

# ---------------------------------------------------------------------------
# Mock libraries (no-crypto, available to all tests)
# ---------------------------------------------------------------------------
add_library(psbt_parse SHARED libs/psbt_parse.c)

# Vendored TOML parser (cktan/tomlc17, MIT). Used by the data-driven
# unit tests that load test vectors from a .toml file.
add_library(tomlc17 STATIC libs/tomlc17.c)
target_include_directories(tomlc17 PUBLIC libs)
# tomlc17 is a third-party source we don't intend to maintain locally —
# silence warnings on it without affecting the rest of the tree.
target_compile_options(tomlc17 PRIVATE -w)

# ---------------------------------------------------------------------------
# App libraries (built standalone for the non-speculos tests)
# ---------------------------------------------------------------------------
add_library(base58      SHARED $ENV{BOLOS_SDK}/lib_standard_app/base58.c)
add_library(bip32       SHARED $ENV{BOLOS_SDK}/lib_standard_app/bip32.c)
add_library(buffer      SHARED $ENV{BOLOS_SDK}/lib_standard_app/buffer.c)
add_library(read        SHARED $ENV{BOLOS_SDK}/lib_standard_app/read.c)
add_library(varint      SHARED $ENV{BOLOS_SDK}/lib_standard_app/varint.c)
add_library(write       SHARED $ENV{BOLOS_SDK}/lib_standard_app/write.c)
add_library(buffer_ext  SHARED ../src/common/buffer_ext.c)
add_library(parser      SHARED ../src/common/parser_ext.c)
add_library(display_utils SHARED ../src/ui/display_utils.c)

# ---------------------------------------------------------------------------
# Test executables (non-speculos)
# ---------------------------------------------------------------------------
# Bare minimum every cmocka-based test needs.
add_library(test_common INTERFACE)
target_link_libraries(test_common INTERFACE cmocka)

function(add_unit_test name)
  cmake_parse_arguments(T "" "" "LIBS;INCLUDES" ${ARGN})
  add_executable(${name} ${name}.c)
  target_link_libraries(${name} PRIVATE ${T_LIBS})
  if(T_INCLUDES)
    target_include_directories(${name} PRIVATE ${T_INCLUDES})
  endif()
  add_test(NAME ${name} COMMAND ${name})
endfunction()

add_unit_test(test_bitvector     LIBS test_common)
add_unit_test(test_buffer        LIBS test_common buffer buffer_ext varint read write bip32)
add_unit_test(test_display_utils LIBS test_common display_utils)
add_unit_test(test_parser        LIBS test_common parser buffer buffer_ext varint read write bip32)
add_unit_test(test_psbt_parse    LIBS test_common psbt_parse)

# ---------------------------------------------------------------------------
# Cleartext binding (host build of the vendored Rust staticlib)
# ---------------------------------------------------------------------------
# The register-wallet handler renders descriptor templates into a human-readable
# description via the no_std Rust crate in ../rust/bip388-c. For the host unit
# tests we build that crate's default (no_std) staticlib with cargo and link it.
# Requires a Rust toolchain: when cargo is absent the cleartext targets are
# skipped and test_register_wallet is built without HAVE_CLEARTEXT (the handler
# then just shows the raw descriptor template, which the tests still verify).
find_program(CARGO_EXECUTABLE cargo)
if(CARGO_EXECUTABLE)
  set(BIP388C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../rust/bip388-c)
  set(BIP388C_LIB ${BIP388C_DIR}/target/release/libbip388_c.a)
  file(GLOB_RECURSE BIP388C_SRCS CONFIGURE_DEPENDS
       ${BIP388C_DIR}/src/*.rs
       ${CMAKE_CURRENT_SOURCE_DIR}/../rust/bip388/src/*.rs
       ${CMAKE_CURRENT_SOURCE_DIR}/../rust/bip388/src/cleartext/specs/*.toml)
  add_custom_command(
    OUTPUT ${BIP388C_LIB}
    COMMAND ${CARGO_EXECUTABLE} build --release
    WORKING_DIRECTORY ${BIP388C_DIR}
    DEPENDS ${BIP388C_SRCS}
    COMMENT "Building host libbip388_c.a"
    VERBATIM)
  add_custom_target(bip388c_lib DEPENDS ${BIP388C_LIB})

  # Thin C wrapper around the binding. HAVE_CLEARTEXT enables the body;
  # CLEARTEXT_HOST_BUILD emits the rust_eh_personality stub needed when linking
  # the no_std staticlib on a hosted target (see src/common/cleartext.c).
  add_library(cleartext STATIC ../src/common/cleartext.c)
  add_dependencies(cleartext bip388c_lib)
  target_compile_definitions(cleartext PRIVATE HAVE_CLEARTEXT CLEARTEXT_HOST_BUILD)
  target_include_directories(cleartext PRIVATE ../src/common ${BIP388C_DIR}/include)
  # PUBLIC so the staticlib (which defines bip388_to_cleartext, and references
  # rust_eh_personality back into cleartext) is on each consumer's link line.
  target_link_libraries(cleartext PUBLIC ${BIP388C_LIB})

  add_unit_test(test_cleartext LIBS test_common cleartext INCLUDES ../src/common)
else()
  message(WARNING "cargo not found: cleartext tests disabled; "
                  "test_register_wallet will be built without HAVE_CLEARTEXT")
endif()

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
  # Speculos paths come first so speculos's own definitions of cx_bn_t /
  # cx_ecpoint_t etc. shadow the SDK ones for the types where they
  # diverge. lib_cxng/include follows so the bridge can pick up the
  # real cx_iovec_t (which speculos doesn't define and the mock_includes
  # version of lcx_common.h omits).
  target_include_directories(speculos_bridge BEFORE PRIVATE
    ${SPECULOS_SRC}/sdk
    ${SPECULOS_SRC}/src
    ${SPECULOS_SRC}/src/bolos
    $ENV{BOLOS_SDK}/lib_cxng/include
  )
  target_link_libraries(speculos_bridge PUBLIC speculos_bolos OpenSSL::Crypto)

  # Build the application code against the real SDK headers so it sees the
  # same syscall signatures the speculos bridge implements. The include
  # paths are added with BEFORE PRIVATE so they take precedence over the
  # global paths set above.
  function(app_apply_real_sdk_config target)
    target_compile_definitions(${target} PRIVATE
      HAVE_HASH HAVE_RIPEMD160 HAVE_SHA256 HAVE_SHA512 HAVE_HMAC HAVE_MATH
      HAVE_ECC HAVE_ECC_WEIERSTRASS HAVE_SECP256K1_CURVE HAVE_ECDSA HAVE_EDDSA
      API_LEVEL=26 OS_IO_SEPH_BUFFER_SIZE=272 IO_USB_MAX_ENDPOINTS=6
      BIP32_PUBKEY_VERSION=0x043587CF BIP44_COIN_TYPE=1
      COIN_P2PKH_VERSION=111 COIN_P2SH_VERSION=196
      COIN_COINID_SHORT=\"TEST\"
    )
    target_include_directories(${target} BEFORE PRIVATE
      ../src
      ../src/common
      ../src/debug-helpers
      ../src/boilerplate
      ../src/handler
      ../src/handler/lib
      ../src/handler/sign_psbt
      ../src/musig
      $ENV{BOLOS_SDK}/target/nanos2/include
      $ENV{BOLOS_SDK}/include
      $ENV{BOLOS_SDK}/io/include
      $ENV{BOLOS_SDK}/io_legacy/include
      $ENV{BOLOS_SDK}/protocol/include
      $ENV{BOLOS_SDK}/lib_standard_app
      $ENV{BOLOS_SDK}/lib_cxng/include
      $ENV{BOLOS_SDK}/lib_cxng/src
      $ENV{BOLOS_SDK}/lib_stusb/include
    )
  endfunction()

  add_library(app_crypto STATIC
    ../src/crypto.c
    ../src/secp256k1.c
    ../src/common/wallet.c
    ../src/common/script.c
    ../src/common/segwit_addr.c
    ../src/common/merkle.c
    ../src/handler/lib/policy.c
    ../src/handler/lib/check_merkle_tree_sorted.c
    ../src/handler/lib/get_merkle_leaf_element.c
    ../src/handler/lib/get_merkle_leaf_hash.c
    ../src/handler/lib/get_merkle_leaf_index.c
    ../src/handler/lib/get_merkle_preimage.c
    ../src/handler/lib/get_merkleized_map.c
    ../src/handler/lib/get_merkleized_map_value.c
    ../src/handler/lib/get_preimage.c
    ../src/handler/lib/stream_merkle_leaf_element.c
    ../src/handler/lib/stream_merkleized_map_value.c
    ../src/handler/lib/stream_preimage.c
    ../src/handler/sign_psbt/extract_bip32_derivation.c
    ../src/handler/sign_psbt/sign_psbt_cache.c
    ../src/musig/musig.c
    $ENV{BOLOS_SDK}/lib_standard_app/crypto_helpers.c
  )
  app_apply_real_sdk_config(app_crypto)
  # Anything linking app_crypto needs the speculos syscall bridge and the
  # SDK helpers the app code calls into. Expose them as PUBLIC so each
  # test only has to mention app_crypto plus its own extras.
  target_link_libraries(app_crypto PUBLIC
    speculos_bridge
    base58 bip32 read write varint
  )

  # mock_dispatcher and xpub need real SDK headers (cx_hash_sha256, crypto.h)
  # and are only used in the speculos-backed tests.
  add_library(mock_dispatcher STATIC libs/mock_dispatcher.c)
  app_apply_real_sdk_config(mock_dispatcher)
  target_link_libraries(mock_dispatcher PUBLIC psbt_parse)

  add_library(xpub STATIC libs/xpub.c)
  app_apply_real_sdk_config(xpub)
  target_link_libraries(xpub PUBLIC base58)

  # Shared dependency bundle for all speculos-backed merkle/handler tests.
  # mock_dispatcher must come before app_crypto so its unresolved refs to
  # merkle_combine_hashes etc. are resolved from app_crypto.a by the linker.
  add_library(test_merkle_common INTERFACE)
  target_link_libraries(test_merkle_common INTERFACE
    cmocka
    mock_dispatcher app_crypto
    buffer buffer_ext varint read write bip32)

  add_unit_test(test_get_preimage              LIBS test_merkle_common)
  add_unit_test(test_get_merkle_preimage       LIBS test_merkle_common)
  add_unit_test(test_extract_bip32_derivation  LIBS test_merkle_common)
  add_unit_test(test_check_merkle_tree_sorted  LIBS test_merkle_common)
  add_unit_test(test_get_merkle_leaf_element   LIBS test_merkle_common)
  add_unit_test(test_get_merkle_leaf_hash      LIBS test_merkle_common)
  add_unit_test(test_get_merkle_leaf_index     LIBS test_merkle_common)
  add_unit_test(test_stream_preimage           LIBS test_merkle_common)
  add_unit_test(test_stream_merkle_leaf_element   LIBS test_merkle_common)
  add_unit_test(test_stream_merkleized_map_value  LIBS test_merkle_common)
  add_unit_test(test_get_merkleized_map        LIBS test_merkle_common)
  add_unit_test(test_get_merkleized_map_value  LIBS test_merkle_common)

  foreach(t
    test_get_preimage test_get_merkle_preimage test_extract_bip32_derivation
    test_check_merkle_tree_sorted test_get_merkle_leaf_element
    test_get_merkle_leaf_hash test_get_merkle_leaf_index test_stream_preimage
    test_stream_merkle_leaf_element test_stream_merkleized_map_value
    test_get_merkleized_map test_get_merkleized_map_value)
    app_apply_real_sdk_config(${t})
  endforeach()

  add_executable(test_crypto test_crypto.c)
  # Compile the test against the real SDK headers too, so that types
  # exposed by crypto.h (e.g. cx_sha256_t) have the same layout the
  # app_crypto object code was built against.
  app_apply_real_sdk_config(test_crypto)
  target_link_libraries(test_crypto PRIVATE cmocka app_crypto xpub)
  add_test(test_crypto test_crypto)

  add_executable(test_script test_script.c)
  app_apply_real_sdk_config(test_script)
  target_link_libraries(test_script PRIVATE cmocka app_crypto)
  add_test(test_script test_script)

  # test_sighash exercises classify_sighash (src/common/sighash.h), which only
  # depends on constants.h (and therefore the real SDK headers). No app object
  # code or syscalls are needed, so it just links cmocka.
  add_executable(test_sighash test_sighash.c)
  app_apply_real_sdk_config(test_sighash)
  target_link_libraries(test_sighash PRIVATE cmocka)
  add_test(test_sighash test_sighash)

  add_executable(test_wallet test_wallet.c)
  app_apply_real_sdk_config(test_wallet)
  target_link_libraries(test_wallet PRIVATE cmocka app_crypto buffer buffer_ext)
  add_test(test_wallet test_wallet)

  # test_get_wallet_address exercises get_wallet_script + get_script_address
  # end-to-end against a mock dispatcher; vectors come from the test assets
  # in the repository root (see ../test_vectors/get_wallet_address.toml).
  add_executable(test_get_wallet_address test_get_wallet_address.c)
  app_apply_real_sdk_config(test_get_wallet_address)
  target_compile_definitions(test_get_wallet_address PRIVATE
    TEST_VECTORS_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/../test_vectors/get_wallet_address.toml\"
  )
  target_link_libraries(test_get_wallet_address PRIVATE
    cmocka mock_dispatcher app_crypto buffer buffer_ext tomlc17
  )
  add_test(test_get_wallet_address test_get_wallet_address)

  # test_get_extended_pubkey exercises handler_get_extended_pubkey (compiled
  # directly into the test) against the vectors in
  # ../test_vectors/get_extended_pubkey.toml. It drives the handler through the
  # mock dispatcher (which backs the response buffer) and provides a capturing
  # stub for the UI symbol the handler references (ui_display_pubkey).
  add_executable(test_get_extended_pubkey
    test_get_extended_pubkey.c
    ../src/handler/get_extended_pubkey.c
  )
  app_apply_real_sdk_config(test_get_extended_pubkey)
  target_include_directories(test_get_extended_pubkey BEFORE PRIVATE ../src/ui)
  target_compile_definitions(test_get_extended_pubkey PRIVATE
    TEST_VECTORS_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/../test_vectors/get_extended_pubkey.toml\"
  )
  target_link_libraries(test_get_extended_pubkey PRIVATE
    cmocka mock_dispatcher app_crypto buffer buffer_ext tomlc17
  )
  add_test(test_get_extended_pubkey test_get_extended_pubkey)

  # test_register_wallet exercises the UI-free core of handler_register_wallet
  # (the handler source is compiled directly into the test) against the vectors
  # in ../test_vectors/register_wallet.toml. It drives the handler through the
  # mock dispatcher (which serves the keys Merkle tree and the descriptor
  # preimage) and provides a stub for the UI symbol the handler references
  # (ui_display_register_wallet_policy).
  add_executable(test_register_wallet
    test_register_wallet.c
    ../src/handler/register_wallet.c
  )
  app_apply_real_sdk_config(test_register_wallet)
  target_include_directories(test_register_wallet BEFORE PRIVATE ../src/ui)
  target_compile_definitions(test_register_wallet PRIVATE
    TEST_VECTORS_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/../test_vectors/register_wallet.toml\"
  )
  target_link_libraries(test_register_wallet PRIVATE
    cmocka mock_dispatcher app_crypto buffer buffer_ext tomlc17
  )
  # Exercise the cleartext path when the binding is available; otherwise the
  # handler (and the test's assertions) fall back to showing the raw template.
  if(TARGET cleartext)
    target_compile_definitions(test_register_wallet PRIVATE HAVE_CLEARTEXT)
    target_link_libraries(test_register_wallet PRIVATE cleartext)
  endif()
  add_test(test_register_wallet test_register_wallet)

  # test_sign_message exercises handler_sign_message (compiled directly into the
  # test) against the vectors in ../test_vectors/sign_message.toml. It drives the
  # handler through the mock dispatcher (which streams back the message chunks)
  # and provides capturing stubs for the UI symbols the handler references.
  add_executable(test_sign_message
    test_sign_message.c
    ../src/handler/sign_message.c
  )
  app_apply_real_sdk_config(test_sign_message)
  target_include_directories(test_sign_message BEFORE PRIVATE ../src/ui)
  target_compile_definitions(test_sign_message PRIVATE
    TEST_VECTORS_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/../test_vectors/sign_message.toml\"
  )
  target_link_libraries(test_sign_message PRIVATE
    cmocka mock_dispatcher app_crypto buffer buffer_ext tomlc17
  )
  add_test(test_sign_message test_sign_message)
endif()
