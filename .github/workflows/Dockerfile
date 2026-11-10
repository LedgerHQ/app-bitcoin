# An image derived from ledgerhq/speculos but also containing the bitcoin-core binaries
# compiled from the master branch

FROM ghcr.io/ledgerhq/speculos:latest

# install git and curl
RUN apt update -y && apt install -y git curl

# install autotools bitcoin-core build dependencies
RUN apt install -y bsdmainutils build-essential cmake pkg-config ccache git libboost-dev libboost-filesystem-dev libboost-system-dev libboost-test-dev libevent-dev libminiupnpc-dev libnatpmp-dev libqt5gui5 libqt5core5a libqt5dbus5 libsqlite3-dev libtool libzmq3-dev pkg-config python3 qttools5-dev qttools5-dev-tools qtwayland5 systemtap-sdt-dev

# clone bitcoin-core from github and compile it
RUN cd / && \
    git clone --depth=1 https://github.com/bitcoin/bitcoin.git && \
    cd bitcoin && \
    cmake -B build -DENABLE_IPC=OFF && \
    cmake --build build && \
    cmake --install build


FROM ghcr.io/ledgerhq/speculos:latest
COPY --from=0 /usr/local/bin/ /usr/local/bin/

# install essential tools
RUN apt update -y && apt install -y build-essential curl git

# install runtime dependencies for bitcoind
RUN apt install -y libminiupnpc-dev libminiupnpc-dev libnatpmp-dev libevent-dev libzmq3-dev

# Add bitcoin binaries to path
ENV PATH=/usr/local/bin/:$PATH

# install a Rust toolchain: the Python client (ledger_bitcoin) that the tests use is built from the
# Rust client. Not in $HOME, which GitHub Actions overrides in job containers.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
ENV PATH=/usr/local/cargo/bin:$PATH
