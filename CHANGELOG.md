# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.2] - 2026-10-08

`v0.7.1` was tagged on `main` but never published. Hatchling emitted
Metadata-Version 2.5 and the pinned `pypa/gh-action-pypi-publish` rejected
the wheel (`InvalidDistribution: '2.5' is not a valid metadata version`).
Re-running that tag would reuse the broken workflow, so this release
carries the same unpublished 0.7.1 client changes plus the publish-action
fix. Tag `v0.7.1` is left in place. No breaking public API changes.

### Changed

- Pin `pypa/gh-action-pypi-publish` to v1.14.2 (Twine 7) so Publish accepts
  hatchling Metadata-Version 2.5 wheels. Trusted publishing / OIDC is
  unchanged.

## [0.7.1] - 2026-10-08

Tagged as `v0.7.1` but never published to PyPI. See 0.7.2.

Patch release of unpublished `main` commits since PyPI `0.7.0` (2026-07-29).
No breaking public API changes.

### Added

- Opt-in `include=["cves"]` on `check` and `batch_check`. Default responses stay compact. Compact and detailed results use separate cache keys, and async coalescing groups by the include flag ([#3](https://github.com/attestd-io/attestd-python/pull/3)).

### Fixed

- Closing `AsyncClient` during the batch coalesce window now fails pending `check()` waiters instead of leaving them hung ([#1](https://github.com/attestd-io/attestd-python/pull/1)).
- `batch_check` raises `AttestdAPIError` when the API returns a `results` list whose length does not match the request ([#5](https://github.com/attestd-io/attestd-python/pull/5)).
- `check` and `batch_check` trim product and version, then reject empty values before they reach the API ([#6](https://github.com/attestd-io/attestd-python/pull/6)).
- `invalidate_cache` uses the same trimmed keys as `check`, so padded arguments actually drop the cached entry ([#7](https://github.com/attestd-io/attestd-python/pull/7)).
- `cve()` rejects empty IDs locally and percent-encodes the path segment ([#8](https://github.com/attestd-io/attestd-python/pull/8)).
- Timeout errors report the timeout as a float (for example `10.0`) instead of an `httpx.Timeout` repr ([#9](https://github.com/attestd-io/attestd-python/pull/9)).

### Documentation

- Package metadata GitHub URLs now point at `attestd-io/attestd-python`. README documents shipped `RiskResult`, typosquat, cache, and retry behavior ([#2](https://github.com/attestd-io/attestd-python/pull/2)).
- README restores the `last_updated` field row and documents that `invalidate_cache` drops both compact and detailed cache entries ([#4](https://github.com/attestd-io/attestd-python/pull/4)).

[0.7.2]: https://github.com/attestd-io/attestd-python/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/attestd-io/attestd-python/compare/v0.7.0...v0.7.1
