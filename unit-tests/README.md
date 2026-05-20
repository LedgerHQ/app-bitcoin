# Unit tests

## Prerequisite

Be sure to have installed:

- CMake >= 3.10
- CMocka >= 1.1.5

and for code coverage generation:

- lcov >= 1.14

On Ubuntu, the following command will install the required dependencies:

```
sudo apt install cmake libcmocka-dev lcov libssl-dev
```

## Overview

In `unit-tests` folder, compile with

```
cmake -Bbuild -H. && make -C build
```

and run tests with

```
CTEST_OUTPUT_ON_FAILURE=1 make -C build test
```

## Speculos-backed crypto tests

A subset of tests links against the C implementation of the BOLOS syscalls provided by
[speculos](https://github.com/LedgerHQ/speculos), removing the need for hand-written per-syscall mocks (usually for cryptography calls).

The speculos sources are fetched automatically at cmake configure time
(pinned to a known-good tag — see `SPECULOS_GIT_TAG` in
`CMakeLists.txt`).

To use an out-of-tree speculos checkout instead of the fetched one:

```
cmake -Bbuild -H. -DSPECULOS_SRC=/path/to/speculos
```

To skip these targets entirely:

```
cmake -Bbuild -H. -DSPECULOS=OFF
```

## Generate code coverage

Just execute in `unit-tests` folder

```
./gen_coverage.sh
```

it will output `coverage.total` and `coverage/` folder with HTML details (in `coverage/index.html`).
