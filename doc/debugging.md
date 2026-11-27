# Debugging

This page contains some information for developers on how to debug failures of the commands of the Ledger Bitcoin app.

## Status Words

Failures in the app's commands are always reported by a corresponding Status Word; see [bitcoin.md](bitcoin.md#status-words) for the currently defined Status Words. Client libraries generally return structured versions of the same Status Words.

The Status Word is contained in the last 2 bytes of the APDU Response, interpreted as a big-endian 16-bit constant.

## Error codes

In addition to the Status Word, some errors provide further details as an _error code_, contained in the first two bytes of the _data_ portion of the reply.

Integrations can ignore the error codes and should not rely on them in production (as they are not guaranteed to be consistent across versions of the app); however, they can provide valuable debugging information for developers working on an integration.

You can see the list of the currently defined error codes in [error_codes.h](../src/error_codes.h).

## Running on Speculos with semihosting

When running the Bitcoin app on the [Speculos](https://github.com/LedgerHQ/speculos) emulator, additional debugging information can be printed on the command line (on the same terminal where Speculos is running) by defining the `DEBUG=10` variable when running the `make` command. See the [ledger-app-builder](https://github.com/LedgerHQ/ledger-app-builder?tab=readme-ov-file#compile-your-app-in-the-container) for instructions on how to build the app for Speculos.

Binaries produced in this way _will_ crash if sideloaded on a real device.

Note: `DEBUG=10` is a feature of the Bitcoin app, and is not used in other Ledger apps.
