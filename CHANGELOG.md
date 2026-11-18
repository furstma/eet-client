# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html);
while the version is 0.x, a minor release may change the API.

## Unreleased

## 0.1.0 - 2026-11-18

### Added

- `Sale`, the sale to be reported. Its values are checked against the official
  schema when it is created.
- `Certificate`, the taxpayer's certificate with its private key, loaded from
  the PKCS#12 file that the certification authority issues.
- `PLAYGROUND` and `PRODUCTION`, the two environments of the service, as
  `Endpoint` values that also say whose signature a confirmation must carry.
- `Confirmation` and `Verification`, the two successful outcomes, with the
  warnings of the service as `ServiceWarning` and their codes as `WarningCode`.
- The exceptions, all under `EETError`: `Unavailable` (report the sale again
  later), its subclass `InvalidReply` (a reply came but cannot be trusted) and
  `Rejected` (do not send again unchanged), with the error codes of the
  service as `ErrorCode`.
- `Client`, which builds and signs a `Message` for a sale, sends it within a
  time limit that covers the whole exchange, and returns the verified
  confirmation. It also sends a sale in verification mode.
