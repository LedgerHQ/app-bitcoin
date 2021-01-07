# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [1.5.5](https://github.com/ledgerhq/app-bitcoin/compare/1.5.4...1.5.5) - 2021-01-06

### Added

- Support for Native Segwit on VertCoin

## [1.5.4](https://github.com/ledgerhq/app-bitcoin/compare/1.5.3...1.5.4) - 2021-01-06

### Fixed

- Remove a change that was breaking swap feature when used with older apps [#180](https://github.com/LedgerHQ/app-bitcoin/pull/180)

### Added

- Tests and GitHub Actions CI

## [1.5.3](https://github.com/ledgerhq/app-bitcoin/compare/1.5.2...1.5.3) - 2020-12-11

### Fixed

- Fix pin validation check on Nano X

## [1.5.2](https://github.com/ledgerhq/app-bitcoin/compare/1.5.1...1.5.2) - 2020-12-10

### Added

- Changelog file

### Removed

- unused `prepare_full_output` and `btchip_bagl_confirm_full_output` functions removed

### Changed

- More errors, less THROWs
- Cleanup args parsing when called as a library

### Fixed

- Most compilation warnings fixed
- Ensure `os_lib_end` is called when errors are encountered in library mode
- Fix pin validation check