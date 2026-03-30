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
print(result.verified)   # True
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
    expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10),
    hmac_secret=HMAC_SECRET,
)
```

### Custom derive_key

Pass your own `derive_key` function to use a custom or third-party KDF:

```python
def my_derive_key(parameters, salt: bytes, password: bytes) -> bytes:
    ...

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

#### `create_challenge(algorithm, cost, *, derive_key, counter, key_length, key_prefix, key_prefix_length, memory_cost, parallelism, expires_at, data, hmac_secret, hmac_key_secret, hmac_algorithm) → Challenge`

Create a new v2 proof-of-work challenge.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `str` | — | KDF algorithm identifier (e.g. `'PBKDF2/SHA-256'`, `'ARGON2ID'`, `'SCRYPT'`, `'SHA-256'`). |
| `cost` | `int` | — | Algorithm-specific cost (iterations / passes). |
| `derive_key` | callable | auto | `(parameters, salt: bytes, password: bytes) -> bytes`. Defaults to built-in for the algorithm. |
| `counter` | `int` | `None` | Pre-solve with this counter (deterministic mode). |
| `key_length` | `int` | `32` | Derived key length in bytes. |
| `key_prefix` | `str` | `'00'` | Hex prefix the derived key must start with. |
| `key_prefix_length` | `int` | `key_length // 2` | Bytes of the derived key used as prefix in deterministic mode. |
| `memory_cost` | `int` | `None` | Memory cost in KiB (Argon2id / scrypt). |
| `parallelism` | `int` | `None` | Parallelism factor (Argon2id / scrypt). |
| `expires_at` | `int` \| `datetime` | `None` | Expiry as a Unix timestamp or `datetime`. |
| `data` | `dict` | `None` | Arbitrary metadata embedded in the challenge. |
| `hmac_secret` | `str` | `None` | Secret for signing the challenge. If omitted, challenge is unsigned. |
| `hmac_key_secret` | `str` | `None` | Secret for signing the derived key (fast verification path). |
| `hmac_algorithm` | `str` | `'SHA-256'` | HMAC digest algorithm. |

Returns `Challenge`.

---

#### `solve_challenge(challenge, derive_key, *, counter_start, counter_step, timeout) → Solution | None`

Solve a v2 challenge by brute-forcing counter values.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `challenge` | `Challenge` | — | The challenge to solve. |
| `derive_key` | callable | auto | KDF function. Defaults to built-in for the algorithm. |
| `counter_start` | `int` | `0` | First counter value to try. |
| `counter_step` | `int` | `1` | Increment between attempts (use > 1 for partitioned parallel solving). |
| `timeout` | `float` | `90.0` | Maximum seconds to spend. Returns `None` on timeout. |

Returns `Solution` or `None`.

---

#### `verify_solution(payload, hmac_secret, derive_key, *, hmac_key_secret, hmac_algorithm) → VerifySolutionResult`

Verify a v2 challenge solution.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `payload` | `str` \| `Payload` | — | Base64-encoded JSON string or `Payload` object. |
| `hmac_secret` | `str` | — | Secret used to verify the challenge signature. |
| `derive_key` | callable | auto | KDF function for re-derivation. |
| `hmac_key_secret` | `str` | `None` | Secret for the fast verification path. |
| `hmac_algorithm` | `str` | `'SHA-256'` | HMAC digest algorithm. |

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

Verifies the hash of specific form fields.

#### `verify_server_signature(payload, hmac_key) → (bool, ServerSignatureVerificationData | None, str | None)`

Verifies an ALTCHA server signature.

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

#### `verify_solution_v1(payload, hmac_secret, check_expires) → (bool, str | None)`

Verifies a v1 solution payload.

#### `solve_challenge_v1(challenge, salt, algorithm, max_number, start) → SolutionV1 | None`

Brute-forces a v1 challenge.

#### `extract_params_v1(payload) → dict`

Extracts URL parameters from the payload's salt.

---

## License

MIT
