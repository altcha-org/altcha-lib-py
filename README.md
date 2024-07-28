# ALTCHA Python Library

The ALTCHA Python Library is a lightweight, zero-dependency library designed for creating and verifying [ALTCHA](https://altcha.org) challenges, specifically tailored for Python applications.

## Compatibility

This library is compatible with:

- Python 3.6+

## Example

- [Demo server](https://github.com/altcha-org/altcha-starter-py)

## Installation

To install the ALTCHA Python Library, use the following command:

```sh
pip install altcha
```

## Build

```sh
python -m build
```

## Tests

```sh
python -m unittest discover tests
```

## Usage

Here’s a basic example of how to use the ALTCHA Python Library:

```python
from altcha import ChallengeOptions, create_challenge, verify_solution

def main():
    hmac_key = "secret hmac key"

    # Create a new challenge
    options = ChallengeOptions(
        max_number=100000, # The maximum random number
        hmac_key=hmac_key,
    )
    challenge = create_challenge(options)
    print("Challenge created:", challenge)

    # Example payload to verify
    payload = {
        "algorithm": challenge.algorithm,
        "challenge": challenge.challenge,
        "number": 12345,  # Example number
        "salt": challenge.salt,
        "signature": challenge.signature,
    }

    # Verify the solution
    ok, err = verify_solution(payload, hmac_key, check_expires=True)
    if err:
        print("Error:", err)
    elif ok:
        print("Solution verified!")
    else:
        print("Invalid solution.")

if __name__ == "__main__":
    main()
```

## API

### `create_challenge(options)`

Creates a new challenge for ALTCHA.

**Parameters:**

- `options (dict)`:
  - `algorithm (str)`: Hashing algorithm to use (`'SHA-1'`, `'SHA-256'`, `'SHA-512'`, default: `'SHA-256'`).
  - `max_number (int)`: Maximum number for the random number generator (default: 1,000,000).
  - `salt_length (int)`: Length of the random salt in bytes (default: 12).
  - `hmac_key (str)`: Required HMAC key.
  - `salt (str)`: Optional salt string. If not provided, a random salt will be generated.
  - `number (int)`: Optional specific number to use. If not provided, a random number will be generated.
  - `expires (datetime)`: Optional expiration time for the challenge.
  - `params (dict)`: Optional URL-encoded query parameters.

**Returns:** `Challenge`

### `verify_solution(payload, hmac_key, check_expires)`

Verifies an ALTCHA solution.

**Parameters:**

- `payload (dict)`: The solution payload to verify.
- `hmac_key (str)`: The HMAC key used for verification.
- `check_expires (bool)`: Whether to check if the challenge has expired.

**Returns:** `(bool, str or None)`

### `extract_params(payload)`

Extracts URL parameters from the payload's salt.

**Parameters:**

- `payload (dict)`: The payload containing the salt.

**Returns:** `dict`

### `verify_fields_hash(form_data, fields, fields_hash, algorithm)`

Verifies the hash of form fields.

**Parameters:**

- `form_data (dict)`: The form data to hash.
- `fields (list)`: The fields to include in the hash.
- `fields_hash (str)`: The expected hash value.
- `algorithm (str)`: Hashing algorithm (`'SHA-1'`, `'SHA-256'`, `'SHA-512'`).

**Returns:** `(bool, str or None)`

### `verify_server_signature(payload, hmac_key)`

Verifies the server signature.

**Parameters:**

- `payload (dict or str)`: The payload to verify (base64 encoded JSON string or dictionary).
- `hmac_key (str)`: The HMAC key used for verification.

**Returns:** `(bool, ServerSignatureVerificationData, str or None)`

### `solve_challenge(challenge, salt, algorithm, max_number, start, stop_chan)`

Finds a solution to the given challenge.

**Parameters:**

- `challenge (str)`: The challenge hash.
- `salt (str)`: The challenge salt.
- `algorithm (str)`: Hashing algorithm (`'SHA-1'`, `'SHA-256'`, `'SHA-512'`).
- `max_number (int)`: Maximum number to iterate to.
- `start (int)`: Starting number.

**Returns:** `(Solution or None, str or None)`

## License

MIT