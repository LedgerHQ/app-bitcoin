#!/bin/bash -eu
# ClusterFuzzLite build: delegate to the shared SDK script.
export BOLOS_SDK=/ledger-secure-sdk
export APP_DIR=/app
exec "${BOLOS_SDK}/fuzzing/scripts/cfl-build.sh"
