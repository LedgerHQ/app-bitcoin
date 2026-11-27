# The environment in which the reusable PyPI deployment workflow builds the Python client
# (bitcoin_client_rs/bindings/python) with `python -m build`: a manylinux image, with a Rust
# toolchain, where maturin tags the wheel as manylinux, which PyPI accepts (when maturin runs as
# a PEP 517 backend, it uses the native `linux` tag by default, which PyPI rejects).

FROM quay.io/pypa/manylinux_2_28_x86_64

ENV PATH=/opt/python/cp312-cp312/bin:$PATH

ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
ENV PATH=/usr/local/cargo/bin:$PATH

ENV MATURIN_PEP517_ARGS="--compatibility manylinux_2_28"
