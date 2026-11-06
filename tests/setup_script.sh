#!/bin/bash
# Installs a pinned release of Bitcoin Core, needed by the end-to-end tests.
#
# The ragger reusable workflow (LedgerHQ/ledger-app-workflows) runs this script
# before the tests. When running on GitHub Actions, the binaries are added to
# $GITHUB_PATH so that `bitcoind` is found by the following steps.
#
# To bump the version, update both BITCOIN_CORE_VERSION and BITCOIN_CORE_SHA256
# (from https://bitcoincore.org/bin/bitcoin-core-<version>/SHA256SUMS).

set -euo pipefail

BITCOIN_CORE_VERSION="32.1"
BITCOIN_CORE_SHA256="61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963"

TARBALL="bitcoin-${BITCOIN_CORE_VERSION}-x86_64-linux-gnu.tar.gz"
URL="https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_CORE_VERSION}/${TARBALL}"
INSTALL_PREFIX="${BITCOIN_CORE_INSTALL_PREFIX:-/opt}"
INSTALL_DIR="${INSTALL_PREFIX}/bitcoin-${BITCOIN_CORE_VERSION}"
BIN_DIR="${INSTALL_DIR}/bin"

# Only use sudo if needed: the ledger-app-dev-tools container runs as root and
# might not have sudo, while /opt is not writable on a bare GitHub runner.
SUDO=""
if ! { mkdir -p "${INSTALL_PREFIX}" 2>/dev/null && [ -w "${INSTALL_PREFIX}" ]; }; then
    SUDO="sudo"
fi

if [ -x "${BIN_DIR}/bitcoind" ]; then
    echo "Bitcoin Core ${BITCOIN_CORE_VERSION} is already installed in ${INSTALL_DIR}"
else
    TMP_DIR="$(mktemp -d)"
    trap 'rm -r "${TMP_DIR}"' EXIT

    echo "Downloading ${URL}"
    curl -fsSL --retry 3 -o "${TMP_DIR}/${TARBALL}" "${URL}"
    echo "${BITCOIN_CORE_SHA256}  ${TMP_DIR}/${TARBALL}" | sha256sum -c -

    ${SUDO} mkdir -p "${INSTALL_PREFIX}"
    ${SUDO} tar -xzf "${TMP_DIR}/${TARBALL}" -C "${INSTALL_PREFIX}"
fi

"${BIN_DIR}/bitcoind" -version | head -n 1

if [ -n "${GITHUB_PATH:-}" ]; then
    echo "${BIN_DIR}" >> "${GITHUB_PATH}"
    echo "Added ${BIN_DIR} to GITHUB_PATH"
else
    echo "Add the binaries to your PATH with:"
    echo "  export PATH=${BIN_DIR}:\$PATH"
fi
