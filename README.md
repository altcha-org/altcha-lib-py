# ALTCHA Python Library

The ALTCHA Python Library is a lightweight, zero-dependency library designed for creating and verifying [ALTCHA](https://altcha.org) challenges, specifically tailored for Python applications.

## Compatibility

- Python 3.9+

## Example

- [`examples/server.py`](/examples/server.py)

## Installation

```sh
pip install altcha
```

For Argon2id support (optional):

```sh
pip install altcha argon2-cffi
```

## Tests

```sh
python -m unittest discover tests
```

---

## PoW v2

PoW v2 replaces the simple hash-matching approach of v1 with a key derivation function (KDF) proof of work. Instead of finding a number whose hash equals a target, the client must find a counter value whose derived key starts with a required prefix. This enables memory-hard algorithms (Argon2id, scrypt) that are more resistant to GPU/ASIC attacks.

### Algorithms

| Algorithm string | KDF | Notes |
|---|---|---|
| `'SHA-256'`, `'SHA-384'`, `'SHA-512'` | Iterated SHA | Fast, for testing / low-security use |
| `'PBKDF2/SHA-256'`, `'PBKDF2/SHA-384'`, `'PBKDF2/SHA-512'` | PBKDF2 | Good default |
| `'SCRYPT'` | scrypt | Memory-hard |
| `'ARGON2ID'` | Argon2id | Memory-hard, requires `argon2-cffi` |

### Quick start

```python
from altcha import (
    create_challenge,
    solve_challenge,
    verify_solution,
    Payload,
)

HMAC_SECRET = "secret hmac key"

# Server: create a challenge
challenge = create_challenge(
    algorithm="PBKDF2/SHA-256",
    cost=5_000,
    hmac_secret=HMAC_SECRET,
)

# Client: solve the challenge
solution = solve_challenge(challenge)
if solution is None:
    raise RuntimeError("Challenge could not be solved in time")

# Client: encode and transmit the payload
payload_b64 = Payload(challenge, solution).to_base64()

# Server: verify
result = verify_solution(payload_b64, HMAC_SECRET)
print(result.verified)  # True
```

### Deterministic mode

Pass a `counter` to `create_challenge` to pre-solve the challenge. The derived key prefix is embedded in the challenge so the client must find exactly that counter. Combine with `hmac_key_secret` to enable fast server-side verification without re-deriving the key.

```python
import secrets

counter = secrets.randbelow(5_000) + 5_000

challenge = create_challenge(
    algorithm="PBKDF2/SHA-256",
    cost=5_000,
    counter=counter,
    hmac_secret=HMAC_SECRET,
    hmac_key_secret="key-signing-secret",
)

solution = solve_challenge(challenge)
if solution is None:
    raise RuntimeError("Challenge could not be solved in time")
payload_b64 = Payload(challenge, solution).to_base64()

result = verify_solution(
    payload_b64,
    HMAC_SECRET,
    hmac_key_secret="key-signing-secret",  # enables fast path
)
print(result.verified)  # True
```

### Expiry

```python
import datetime

challenge = create_challenge(
    algorithm="PBKDF2/SHA-256",
    cost=5_000,
    expires_at=datetime.datetime.now(datetime.timezone.utc)
    + datetime.timedelta(minutes=10),
    hmac_secret=HMAC_SECRET,
)
```

### Custom derive_key

Pass your own `derive_key` function to use a custom or third-party KDF:

```python
def my_derive_key(parameters, salt: bytes, password: bytes) -> bytes: ...


challenge = create_challenge(
    algorithm="MY-ALGO",
    cost=1,
    derive_key=my_derive_key,
    hmac_secret=HMAC_SECRET,
)
```

---

## PoW v1 (legacy)

The original ALTCHA proof of work. The client brute-forces a number `n` such that `hash(salt + n) == challenge`. Available under the `_v1` / `V1` suffix.

---

## API reference

### V2

#### `create_challenge(algorithm, cost, *, derive_key, counter, counter_mode, key_length, key_prefix, key_prefix_length, memory_cost, parallelism, expires_at, data, hmac_secret, hmac_key_secret, hmac_algorithm) → Challenge`

Create a new v2 proof-of-work challenge.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `str` | — | KDF algorithm identifier (e.g. `'PBKDF2/SHA-256'`, `'ARGON2ID'`, `'SCRYPT'`, `'SHA-256'`). |
| `cost` | `int` | — | Algorithm-specific cost (iterations / passes). |
| `derive_key` | callable | auto | `(parameters, salt: bytes, password: bytes) -> bytes`. Defaults to built-in for the algorithm. |
| `counter` | `int` | `None` | Pre-solve with this counter (deterministic mode). |
| `counter_mode` | `str` | `'uint32'` | Counter encoding in the KDF password: `'uint32'` (big-endian) or `'string'` (decimal digits, V1 compatibility). Solver and verifier must use the same mode. |
| `key_length` | `int` | `32` | Derived key length in bytes. |
| `key_prefix` | `str` | `'00'` | Hex prefix the derived key must start with. |
| `key_prefix_length` | `int` | `key_length // 2` | Bytes of the derived key used as prefix in deterministic mode. |
| `memory_cost` | `int` | `None` | Memory cost in KiB (Argon2id / scrypt). |
| `parallelism` | `int` | `None` | Parallelism factor (Argon2id / scrypt). |
| `expires_at` | `int` \| `datetime` | `None` | Expiry as a Unix timestamp or `datetime`. |
| `data` | `dict` | `None` | Arbitrary metadata embedded in the challenge. |
| `hmac_secret` | `str` | `None` | Secret for signing the challenge. If omitted or empty, challenge is unsigned. |
| `hmac_key_secret` | `str` | `None` | Secret for signing the derived key (fast verification path). Ignored if empty. |
| `hmac_algorithm` | `str` | `'SHA-256'` | HMAC digest algorithm. |

Returns `Challenge`.

---

#### `solve_challenge(challenge, derive_key, *, counter_start, counter_step, timeout, counter_mode) → Solution | None`

Solve a v2 challenge by brute-forcing counter values.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `challenge` | `Challenge` | — | The challenge to solve. |
| `derive_key` | callable | auto | KDF function. Defaults to built-in for the algorithm. |
| `counter_start` | `int` | `0` | First counter value to try. |
| `counter_step` | `int` | `1` | Increment between attempts (use > 1 for partitioned parallel solving). |
| `timeout` | `float` | `90.0` | Maximum seconds to spend. Returns `None` on timeout. |
| `counter_mode` | `str` | `'uint32'` | Counter encoding; must match the issuer's. |

Returns `Solution` or `None`.

---

#### `verify_solution(payload, hmac_secret, derive_key, *, hmac_key_secret, hmac_algorithm, counter_mode) → VerifySolutionResult`

Verify a v2 challenge solution.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `payload` | `str` \| `Payload` | — | Base64-encoded JSON string or `Payload` object. |
| `hmac_secret` | `str` | — | Secret used to verify the challenge signature. Raises `ValueError` if empty. |
| `derive_key` | callable | auto | KDF function for re-derivation. |
| `hmac_key_secret` | `str` | `None` | Secret for the fast verification path. |
| `hmac_algorithm` | `str` | `'SHA-256'` | HMAC digest algorithm. |
| `counter_mode` | `str` | `'uint32'` | Counter encoding used when re-deriving the key; must match the issuer's. |

Returns `VerifySolutionResult` with fields:

| Field | Type | Description |
|---|---|---|
| `verified` | `bool` | `True` if the solution is valid. |
| `expired` | `bool` | `True` if the challenge has expired. |
| `invalid_signature` | `bool \| None` | `True` if the challenge signature is missing or wrong. |
| `invalid_solution` | `bool \| None` | `True` if the solution is incorrect. |
| `time` | `float` | Time taken for verification in milliseconds. |
| `error` | `str \| None` | Set if the payload could not be parsed. |

---

#### Built-in derive_key functions

| Function | Algorithm |
|---|---|
| `derive_key_sha(parameters, salt, password)` | Iterated SHA (SHA-256/384/512) |
| `derive_key_pbkdf2(parameters, salt, password)` | PBKDF2 (SHA-256/384/512) |
| `derive_key_scrypt(parameters, salt, password)` | scrypt |
| `derive_key_argon2id(parameters, salt, password)` | Argon2id (requires `argon2-cffi`) |

---

### Server Signature Verification

#### `verify_fields_hash(form_data, fields, fields_hash, algorithm) → bool`

Verifies the hash of specific form fields: the hex hash (`algorithm`, e.g. `'SHA-256'`) of
the values of `fields` in `form_data`, joined with `\n`, must equal `fields_hash`.

#### `verify_server_signature(payload, hmac_secret, *, hmac_algorithm) → VerifyServerSignatureResult`

Verifies an ALTCHA server signature locally, e.g. the `payload` of Sentinel's
`POST /v2/verify` (or `/v1/verify`) response, with the secret of the API key that signed
it. Sentinel v1 and v2 sign the same way, so this works for both. To have Sentinel check
the payload instead, use `verify_server` (below).

```python
from altcha import verify_fields_hash, verify_server_signature

result = verify_server_signature(payload, API_KEY_SECRET)

if result.verified:
    data = result.verification_data
    # Detect tampering with the submitted form fields
    if data.get("fields") and not verify_fields_hash(
        form_data, data["fields"], data["fieldsHash"], "SHA-256"
    ):
        ...
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `payload` | `str` \| `ServerSignaturePayload` | — | Base64-encoded JSON string or `ServerSignaturePayload` object. Its `algorithm` (hash of `verificationData`) must be `'SHA-1'`, `'SHA-256'`, `'SHA-384'` or `'SHA-512'`. |
| `hmac_secret` | `str` \| `bytes` | — | Secret used to verify the HMAC signature (the API key secret for Sentinel). Raises `ValueError` if empty. |
| `hmac_algorithm` | `str` | `'SHA-256'` | HMAC digest algorithm. |

Returns `VerifyServerSignatureResult` with fields:

| Field | Type | Description |
|---|---|---|
| `verified` | `bool` | `True` if the signature is valid, the payload has not expired, and `verified` is `true` in both the payload and the signed verification data. |
| `expired` | `bool` | `True` if the signed `expire` is in the past. |
| `invalid_signature` | `bool` | `True` if the signature does not match, or the payload is malformed. |
| `invalid_solution` | `bool` | `True` if `verified` is not `true` in the payload or in the signed verification data. |
| `time` | `float` | Time taken for verification in milliseconds. |
| `verification_data` | `dict \| None` | The signed verification data, parsed with `parse_verification_data`; `None` unless `verified`. |

`parse_verification_data(data)` turns the URL-encoded verification data into a flat dict:

- Keys stay as signed, e.g. `data["challenge.algorithm"]` and `data["device.edk"]`
  (`verify_server` returns these nested instead).
- `'true'`/`'false'` become `bool`, all-digit values `int` (including e.g. a
  `params.zip` of `01234`, which becomes `1234`), and `digits.digits` values `float`.
- `fields` and `reasons` become lists.
- Keys with empty values are left out.

Unlike Sentinel v2's `/v2/verify/signature` (via `verify_server`), local verification does
not prevent reuse: a valid payload verifies again until `expire`. Reject repeated `id`s
yourself if that matters.

#### `verify_server(payload, url, secret, *, api_key, headers, timeout, retries, retry_delay, retry_backoff, http_post) → VerifyServerResult`

Verifies a payload remotely via the ALTCHA Sentinel verify signature API, instead of
checking the HMAC signature locally. Avoids managing the HMAC secret on your server, at the
cost of a network round-trip. Both Sentinel v2 (`POST /v2/verify/signature`) and Sentinel v1
(`POST /v1/verify/signature`) are supported; they differ in how the request is authenticated.

##### Sentinel v2

```python
from altcha import verify_server

result = verify_server(
    payload,  # the payload received from POST /v2/verify
    url="https://sentinel.example.com/v2/verify/signature",
    api_key=SENTINEL_API_KEY,  # id of a restricted or full API key (key_...)
    secret=SENTINEL_API_KEY_SECRET,  # its secret (sec_...)
    timeout=10,
    retries=2,
)

if result.verified:
    ...
```

- `api_key` and `secret` are the ID and secret of a `restricted` or `full` API key of the
  account that owns the payload's (public) API key. They are sent as
  `Authorization: Basic base64(api_key:secret)`; an `Authorization` header in `headers` is
  replaced. `api_key` without `secret` raises `ValueError` before any request is sent.
- The request body is `{"payload": ...}`; `secret` is not sent in the body (Sentinel v2
  rejects it).
- Without credentials, Sentinel v2 answers `401` and `reason` is `'API_KEY_REQUIRED'`. A
  payload signed by a key of another account gets `reason='API_KEY_NOT_ALLOWED'`.
- `verification_data` is the signed verification data as a nested dict, with keys split on
  `.`: `result.verification_data["challenge"]["algorithm"]` (v1's `challengeAlgorithm`),
  `result.verification_data["device"]["edk"]`. `fields` and `reasons` are lists; `id`,
  `fieldsHash`, `device.edk` and `params.*` stay strings.

##### Sentinel v1

```python
from altcha import verify_server

result = verify_server(
    payload,  # the payload received from POST /v1/verify
    url="https://sentinel.example.com/v1/verify/signature",
    secret=API_KEY_SECRET,  # optional, checked against the payload's API key
    timeout=10,
    retries=2,
)

if result.verified:
    ...
```

- `/v1/verify/signature` takes no credentials: omit `api_key`. `secret` (the payload's API
  key secret) is optional and sent in the body as `{"payload": ..., "secret": ...}`; Sentinel
  answers `reason='WRONG_API_KEY_SECRET'` when it is not the payload key's secret.
- This also applies to the `/v1/verify/signature` alias Sentinel v2 serves with
  `[server] v1_compat = true`.

##### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `payload` | `str` \| `ServerSignaturePayload` \| `dict` | — | The payload to verify. |
| `url` | `str` | — | Full URL of the Sentinel endpoint: `/v2/verify/signature` (v2) or `/v1/verify/signature` (v1). |
| `secret` | `str` | `None` | v2: secret of `api_key`, required with it. v1: API key secret sent in the body and checked against the payload's API key. |
| `api_key` | `str` | `None` | v2 only: ID of a `restricted` or `full` API key, sent with `secret` as HTTP Basic credentials. |
| `headers` | `dict` | `None` | Additional headers to send with the request. |
| `timeout` | `float` | `10` | Per-attempt request timeout in seconds. |
| `retries` | `int` | `0` | Number of retry attempts after the first try. |
| `retry_delay` | `float` | `0.3` | Base delay in seconds between retries. |
| `retry_backoff` | `str` | `'exponential'` | `'fixed'` or `'exponential'` backoff. |
| `http_post` | callable | stdlib `urllib` | Transport override: `(url, body, headers, timeout) -> (status, body)`. |

##### Errors and retries

Failures never raise; they return `verified=False` with a `reason`. `4xx` responses (bad
payload, missing or wrong credentials, rate limit) are definitive and returned at once.
Network errors, other error statuses (e.g. `5xx`) and invalid response bodies are retried up
to `retries` times. For an error response, `reason` is the `code` of Sentinel's error body
(v2: `{"code", "error", "statusCode"}`), else its `error` (v1), else `'HTTP_<status>'`.

Returns `VerifyServerResult` with fields:

| Field | Type | Description |
|---|---|---|
| `verified` | `bool` | `True` if Sentinel confirmed the payload is valid. |
| `reason` | `str \| None` | Why verification failed: Sentinel's `reason` (e.g. `'PAYLOAD_ALREADY_USED'`, `'INVALID_PAYLOAD'`, `'API_KEY_NOT_ALLOWED'` (v2), `'WRONG_API_KEY_SECRET'` (v1)), the error code of an HTTP error response, `'INVALID_RESPONSE'`, or a network error message. |
| `api_key` | `str \| None` | The API key associated with the payload, if returned. |
| `verification_data` | `dict \| None` | Verification data returned by Sentinel (nested dict), if returned. |

---

### V1 (legacy)

#### `create_challenge_v1(options) → ChallengeV1`

Creates a new v1 challenge.

**`ChallengeOptionsV1` parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `str` | `'SHA-256'` | Hashing algorithm (`'SHA-1'`, `'SHA-256'`, `'SHA-512'`). |
| `max_number` | `int` | `1,000,000` | Upper bound for the random number. |
| `salt_length` | `int` | `12` | Length of the random salt in bytes. |
| `hmac_key` | `str` | — | Required HMAC key. |
| `salt` | `str` | auto | Optional salt. Random if omitted. |
| `number` | `int` | auto | Optional number. Random if omitted. |
| `expires` | `datetime` | `None` | Optional expiration time. |
| `params` | `dict` | `None` | Optional URL-encoded query parameters appended to the salt. |

#### `verify_server_signature_v1(payload, hmac_key) → (bool, ServerSignatureVerificationData | None, str | None)`

Verifies a server signature with the v1 API. Returns `(verified, data, error)`, where `data`
exposes the known fields (`classification`, `expire`, `fields`, `fieldsHash`, `score`, …)
as attributes. Prefer `verify_server_signature`.

#### `verify_solution_v1(payload, hmac_secret, check_expires) → (bool, str | None)`

Verifies a v1 solution payload.

#### `solve_challenge_v1(challenge, salt, algorithm, max_number, start) → SolutionV1 | None`

Brute-forces a v1 challenge.

#### `extract_params_v1(payload) → dict`

Extracts URL parameters from the payload's salt.

---

## License

MIT
