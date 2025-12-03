## [0.2.0] - 2025-12-03

### Added
- "Prefix reducer".
  - It replaces up to 13 different prefixes with a 1-byte marker that was found more than 3 times.
  - Define `UTFC__PREFIX_REDUCER_THRESHOLD` with the value `UINT32_MAX` to prevent this new feature.

### Changed
- The reserved length for bytes has been increased from `50` to `500`.
  - The maximum allowed length for a string has changed from `UINT32_MAX - 50` to `UINT32_MAX - 500`.

General internal improvements...

## [0.1.0] - 2025-11-11