# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.4.0] - 2026-11-17

### Added

- `verify_server` supports Sentinel v2's `POST /v2/verify/signature`. Pass the ID and
  secret of a `restricted` or `full` API key as `api_key` and `secret`: they are sent as
  HTTP Basic credentials and `secret` is left out of the body. `api_key` without `secret`
  raises `ValueError`. Sentinel v1 (`/v1/verify/signature`) works as before when `api_key`
  is omitted.
- `ServerSignaturePayload` carries the optional `apiKey` and `id` fields (`api_key`, `id`)
  and keeps them in `to_dict`, so a payload object passed to `verify_server` still names
  its signing key.

### Changed

- `verify_server` no longer retries `4xx` responses (e.g. `401`/`403` for missing or wrong
  credentials, `429`); they return `verified=False` at once. For error responses, `reason`
  is the body's `code`, else its `error`, else `HTTP_<status>`; `5xx` responses that
  exhaust the retries report it too (was always `HTTP_<status>`).

### Fixed

- `verify_server` returns `reason='INVALID_RESPONSE'` (after retrying) instead of raising
  when a `2xx` response body is not a JSON object.

## [2.3.0] - 2026-10-04

Aligns the v2 API (`altcha.v2`) with the reference JavaScript implementation
([altcha-lib](https://github.com/altcha-org/altcha-lib)) and hardens verification
against malformed payloads.

### Upgrade notes

- Challenges signed by earlier versions may fail verification after upgrading if
  their `data` contains `None`, floats, integer-like keys, or integers above 2^53, or
  if they use a non-standard algorithm string (e.g. `'sha-512'`, `'SHA-1'`). Other
  challenges keep the same signature and derived key. Challenges are short-lived, so
  this only affects challenges issued just before the upgrade.
- `verify_solution` and `verify_server_signature` raise `ValueError` if `hmac_secret`
  is empty.

### Added

- `counter_mode` option (`'uint32'` default, or `'string'`) for `create_challenge`,
  `solve_challenge` and `verify_solution`, matching altcha-lib's `counterMode`.
  `'string'` encodes the counter as decimal digits, as in v1-compatible challenges.

### Changed

- Challenge signatures use canonical JSON that is byte-identical to altcha-lib's
  `canonicalJSON`. `null` values are kept. Numbers are formatted as in JavaScript
  (`1e-7`, `1` for `1.0`, integers above 2^53 rounded to a double, `NaN` and
  `Infinity` as `null`). Integer-like keys come first in numeric order, and other
  keys are sorted by UTF-16 code units. Dicts inside arrays keep their key order, and
  lone surrogates are escaped.
- Built-in SHA and PBKDF2 key derivation selects SHA-384 or SHA-512 only for the exact
  algorithm strings `SHA-384`, `SHA-512`, `PBKDF2/SHA-384` and `PBKDF2/SHA-512`. Any
  other string falls back to SHA-256, as in altcha-lib.
- `create_challenge` stores `key_prefix` in lowercase.
- `create_challenge` treats an empty `hmac_secret` as unset (unsigned challenge) and an
  empty `hmac_key_secret` as unset (no `keySignature`).
- `create_challenge` raises `ValueError` when signing `data` that contains a
  `__proto__` key outside arrays. altcha-lib leaves such keys out of the signature, so
  they are rejected instead. Payloads containing them fail verification with
  `invalid_signature`.
- `verify_server_signature` accepts only `SHA-1`, `SHA-256`, `SHA-384` and `SHA-512` as
  the payload `algorithm`. These are the digests available to altcha-lib.

### Fixed

- `verify_solution` returns a result instead of raising on malformed client input:
  - non-hex, odd-length or non-string `derivedKey`;
  - non-integer or out-of-range `counter`;
  - non-string or non-ASCII `signature` or `derivedKey`;
  - non-numeric `expiresAt`;
  - deeply nested `data`.
- With `hmac_key_secret`, a `derivedKey` containing whitespace no longer verifies.
- `verify_server_signature` returns `invalid_signature` instead of raising on a
  malformed `algorithm` or `verificationData`. Lone surrogates in `verificationData`
  are hashed as JavaScript's `TextEncoder` encodes them.
- `solve_challenge` now enforces `timeout` when `counter_start` and `counter_step`
  never reach a multiple of 10 (e.g. `1` and `2`). Previously it could run forever.
- Uppercase key prefixes from other issuers: `verify_solution` no longer rejects valid
  solutions for even-length prefixes, and `solve_challenge` now solves odd-length ones.
- Challenges issued by altcha-lib with explicit `null` parameters (`data`, `expiresAt`,
  `memoryCost`, `parallelism`) now verify.
- Challenges whose `data` contains `null` or floats now verify between this library
  and altcha-lib in both directions.
