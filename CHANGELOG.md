# Changelog

All notable changes to this project will be documented in this file.

## [0.5.1] - 2025-04-13
### Fixed
- Improved warning log message when `header_key` is not found in the secret by including the secret name.

## [0.5.0] - 2025-04-13
### Added
- `header_key` feature to support OTEL_EXPORTER_OTLP_HEADERS format
- New example configurations demonstrating `header_key` usage
- Comprehensive tests for the new feature

### Changed
- Updated documentation to explain the new feature and its usage
- Improved error handling for header parsing

### Fixed
- Removed unused code in tests

## [0.2.0] - 2025-04-10
### Added
- Header prefix feature to selectively include secret keys as headers
- Compatibility with OpenTelemetry Collector v0.119.0
- GitHub Actions workflow for testing and automated tagging
- VERSION file for version management

### Changed
- Stability level set to **alpha**
- Updated documentation and examples

### Fixed
- Improved test coverage for header prefix filtering

---

## [0.1.0] - 2024-xx-xx
### Added
- Initial release of AWS Secrets Manager Authenticator Extension
