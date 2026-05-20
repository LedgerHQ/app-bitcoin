#!/bin/bash -eu
# ClusterFuzzLite build for the Bitcoin Absolution-driven fuzz pipeline.
#
# Drives the SDK's manual fuzz-build workflow (the helpers behind
# app-campaign.sh) so the build is robust to global-layout drift between
# the dev machine that last committed fuzz_globals.zon and CFL's three
# sanitizer matrix entries (address / undefined / memory). Each sanitizer
# shifts the global memory layout (ASan red zones, MSan shadow, etc.),
# which makes a single committed .zon incompatible with all three. We
# therefore bootstrap the invariant to `.{}` on every CI build, let
# Absolution discover globals fresh, then resync the .zon via the SDK's
# sync_invariant helper before the final build.
#
# Maps CFL's SANITIZER env into the SDK's APP_SANITIZER so configure_fuzz_build
# picks the matching sanitizer profile for the current matrix entry.

export BOLOS_SDK=/ledger-secure-sdk
export APP_DIR=/app
export APP_TARGET=flex
export APP_SANITIZER="${SANITIZER:-address}"

SCRIPT_DIR="${BOLOS_SDK}/fuzzing/scripts"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/app-common.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/app-config.sh"

BUILD_FAST="${APP_DIR}/build/fast"
INV="${APP_DIR}/fuzzing/invariants/fuzz_globals.zon"
LAYOUT="${APP_DIR}/fuzzing/mock/scenario_layout.h"

echo '.{}' > "${INV}"

rm -rf "${BUILD_FAST}"

configure_fuzz_build "${APP_DIR}" "${BUILD_FAST}" RelWithDebInfo 0
build_fuzzer_target "${BUILD_FAST}" fuzz_app

INVARIANT_CHANGED=0
sync_invariant "${BUILD_FAST}" fuzz_app "${INV}"
if [[ "${INVARIANT_CHANGED}" == "1" ]]; then
    build_fuzzer_target "${BUILD_FAST}" fuzz_app
fi

update_scenario_layout "${BUILD_FAST}" fuzz_app "${LAYOUT}"
cmake --build "${BUILD_FAST}"

cp "${BUILD_FAST}/fuzz_app" "${OUT}/"

if [ -d "${APP_DIR}/fuzzing/base-corpus" ]; then
    echo "Zipping base-corpus into fuzz_app_seed_corpus.zip"
    (cd "${APP_DIR}/fuzzing/base-corpus" && \
        zip -q -r "${OUT}/fuzz_app_seed_corpus.zip" .)
fi
