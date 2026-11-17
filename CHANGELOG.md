# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html);
while the version is 0.x, a minor release may change the API.

## Unreleased

### Added

- `Sale`, the sale to be reported. Its values are checked against the official
  schema when it is created.
- `Certificate`, the taxpayer's certificate with its private key, loaded from
  the PKCS#12 file that the certification authority issues.
