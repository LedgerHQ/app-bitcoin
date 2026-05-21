FROM gcr.io/oss-fuzz-base/base-builder:v1

RUN pip3 install --break-system-packages --no-cache-dir pillow>=3.4.0
RUN apt update && apt install -y ninja-build zip libbsd-dev pkg-config git

ARG LEDGER_SECURE_SDK_REPO=https://github.com/LedgerHQ/ledger-secure-sdk.git
ARG LEDGER_SECURE_SDK_REF=09c67f3b6d7f51306266a1b26e154dff5b65e634
RUN git init /ledger-secure-sdk \
    && cd /ledger-secure-sdk \
    && git remote add origin "${LEDGER_SECURE_SDK_REPO}" \
    && git fetch --depth 1 origin "${LEDGER_SECURE_SDK_REF}" \
    && git checkout FETCH_HEAD \
    && test -f fuzzing/cmake/LedgerAppFuzz.cmake \
    && echo "Ledger fuzz framework present at ${LEDGER_SECURE_SDK_REF}"
COPY . /app
WORKDIR /app
COPY ./.clusterfuzzlite/build.sh $SRC/