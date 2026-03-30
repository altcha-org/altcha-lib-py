from __future__ import annotations

import hashlib
import hmac as _hmac_module
import base64
import json
import re
import secrets
import struct
import time
import urllib.parse
from typing import Callable, Literal
import datetime

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

HmacAlgorithmV2 = Literal["SHA-256", "SHA-384", "SHA-512"]

DEFAULT_KEY_LENGTH: int = 32
DEFAULT_KEY_PREFIX: str = "00"
DEFAULT_HMAC_ALGORITHM: HmacAlgorithmV2 = "SHA-256"

DeriveKeyFunctionV2 = Callable[["ChallengeParameters", bytes, bytes], bytes]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class ChallengeParameters:
    """
    Parameters embedded in a v2 challenge.

    Attributes:
        algorithm: Key derivation algorithm (e.g. 'PBKDF2/SHA-256', 'ARGON2ID', 'SCRYPT', 'SHA-256').
        nonce: Random 16-byte hex string used as the KDF password prefix.
        salt: Random 16-byte hex string used as the KDF salt.
        cost: Algorithm-specific cost parameter (iterations / time cost).
        key_length: Derived key length in bytes. Defaults to 32.
        key_prefix: Hex prefix the derived key must start with to solve the challenge.
        key_signature: Optional HMAC of the derived key for fast server-side verification.
        memory_cost: Memory cost in KiB (Argon2id / scrypt only).
        parallelism: Parallelism factor (Argon2id / scrypt only).
        expires_at: Unix timestamp (seconds) after which the challenge is invalid.
        data: Arbitrary metadata embedded in the challenge.
    """

    def __init__(
        self,
        algorithm: str,
        nonce: str,
        salt: str,
        cost: int,
        key_length: int = DEFAULT_KEY_LENGTH,
        key_prefix: str = DEFAULT_KEY_PREFIX,
        key_signature: str | None = None,
        memory_cost: int | None = None,
        parallelism: int | None = None,
        expires_at: int | None = None,
        data: dict | None = None,
    ):
        self.algorithm = algorithm
        self.nonce = nonce
        self.salt = salt
        self.cost = cost
        self.key_length = key_length
        self.key_prefix = key_prefix
        self.key_signature = key_signature
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.expires_at = expires_at
        self.data = data

    def to_dict(self) -> dict:
        """Return a camelCase dict suitable for JSON serialization / signing."""
        d: dict = {
            "algorithm": self.algorithm,
            "cost": self.cost,
            "keyLength": self.key_length,
            "keyPrefix": self.key_prefix,
            "nonce": self.nonce,
            "salt": self.salt,
        }
        if self.key_signature is not None:
            d["keySignature"] = self.key_signature
        if self.memory_cost is not None:
            d["memoryCost"] = self.memory_cost
        if self.parallelism is not None:
            d["parallelism"] = self.parallelism
        if self.expires_at is not None:
            d["expiresAt"] = self.expires_at
        if self.data is not None:
            d["data"] = self.data
        return d

    @classmethod
    def from_dict(cls, d: dict) -> ChallengeParameters:
        return cls(
            algorithm=d["algorithm"],
            nonce=d["nonce"],
            salt=d["salt"],
            cost=d["cost"],
            key_length=d.get("keyLength", DEFAULT_KEY_LENGTH),
            key_prefix=d.get("keyPrefix", DEFAULT_KEY_PREFIX),
            key_signature=d.get("keySignature"),
            memory_cost=d.get("memoryCost"),
            parallelism=d.get("parallelism"),
            expires_at=d.get("expiresAt"),
            data=d.get("data"),
        )


class Challenge:
    """
    A v2 proof-of-work challenge sent to the client.

    Attributes:
        parameters: The KDF parameters the client must solve.
        signature: HMAC of the canonical JSON of parameters (prevents tampering).
    """

    def __init__(
        self,
        parameters: ChallengeParameters,
        signature: str | None = None,
    ):
        self.parameters = parameters
        self.signature = signature

    def to_dict(self) -> dict:
        d: dict = {"parameters": self.parameters.to_dict()}
        if self.signature is not None:
            d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Challenge:
        return cls(
            parameters=ChallengeParameters.from_dict(d["parameters"]),
            signature=d.get("signature"),
        )


class Solution:
    """
    A v2 challenge solution found by the client.

    Attributes:
        counter: The counter value that produced a matching derived key.
        derived_key: Hex-encoded derived key.
        time: Time taken to solve in milliseconds (optional).
    """

    def __init__(self, counter: int, derived_key: str, time: float | None = None):
        self.counter = counter
        self.derived_key = derived_key
        self.time = time

    def to_dict(self) -> dict:
        d: dict = {"counter": self.counter, "derivedKey": self.derived_key}
        if self.time is not None:
            d["time"] = self.time
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Solution:
        return cls(
            counter=d["counter"],
            derived_key=d["derivedKey"],
            time=d.get("time"),
        )


class Payload:
    """
    A complete v2 payload (challenge + solution) transmitted from the client.

    Attributes:
        challenge: The challenge that was solved.
        solution: The solution found by the client.
    """

    def __init__(self, challenge: Challenge, solution: Solution):
        self.challenge = challenge
        self.solution = solution

    def to_dict(self) -> dict:
        return {
            "challenge": self.challenge.to_dict(),
            "solution": self.solution.to_dict(),
        }

    def to_base64(self) -> str:
        return base64.b64encode(json.dumps(self.to_dict()).encode()).decode()

    @classmethod
    def from_base64(cls, data: str) -> Payload:
        d = json.loads(base64.b64decode(data).decode())
        return cls(
            challenge=Challenge.from_dict(d["challenge"]),
            solution=Solution.from_dict(d["solution"]),
        )


class VerifySolutionResult:
    """
    The result of a v2 solution verification.

    Attributes:
        expired: True if the challenge has expired.
        invalid_signature: True if the challenge signature is missing or invalid.
        invalid_solution: True if the solution is incorrect.
        time: Time taken for verification in milliseconds.
        verified: True if the solution is valid.
        error: Human-readable error message if parsing failed.
    """

    def __init__(
        self,
        expired: bool,
        invalid_signature: bool | None,
        invalid_solution: bool | None,
        time: float,
        verified: bool,
        error: str | None = None,
    ):
        self.expired = expired
        self.invalid_signature = invalid_signature
        self.invalid_solution = invalid_solution
        self.time = time
        self.verified = verified
        self.error = error


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_password(nonce: bytes, counter: int) -> bytes:
    """Combine nonce and counter (uint32 big-endian) into a KDF password buffer."""
    return nonce + struct.pack(">I", counter)


def _buffer_starts_with(buf: bytes, prefix: bytes) -> bool:
    if len(prefix) > len(buf):
        return False
    return buf[: len(prefix)] == prefix


def _sort_keys(obj: object) -> object:
    """Recursively sort dict keys; exclude None values (equivalent to JS undefined)."""
    if isinstance(obj, dict):
        return {k: _sort_keys(v) for k, v in sorted(obj.items()) if v is not None}
    if isinstance(obj, list):
        return [_sort_keys(item) for item in obj]
    return obj


def _canonical_json(obj: dict) -> str:
    """Produce a sorted-key, compact JSON string for deterministic signing."""
    return json.dumps(_sort_keys(obj), separators=(",", ":"), ensure_ascii=False)


def _hmac_v2(algorithm: str, data: str | bytes, key: str) -> bytes:
    """Compute HMAC and return raw bytes."""
    if isinstance(data, str):
        data = data.encode()
    hash_name = algorithm.lower().replace("-", "")  # 'sha256', 'sha384', 'sha512'
    return _hmac_module.new(key.encode(), data, getattr(hashlib, hash_name)).digest()


def _constant_time_equal(a: str, b: str) -> bool:
    return _hmac_module.compare_digest(a, b)


def _sign_challenge_v2(
    hmac_algorithm: str,
    parameters: ChallengeParameters,
    derived_key: bytes | None,
    hmac_secret: str,
    hmac_key_secret: str | None = None,
) -> Challenge:
    """Sign challenge parameters with HMAC, optionally also signing the derived key."""
    if derived_key is not None and hmac_key_secret is not None:
        parameters.key_signature = _hmac_v2(
            hmac_algorithm, derived_key, hmac_key_secret
        ).hex()

    params_dict = parameters.to_dict()
    canonical = _canonical_json(params_dict)
    signature = _hmac_v2(hmac_algorithm, canonical, hmac_secret).hex()
    return Challenge(parameters=parameters, signature=signature)


# ---------------------------------------------------------------------------
# Key derivation algorithms
# ---------------------------------------------------------------------------


def _sha_digest(algorithm: str) -> str:
    """Map algorithm string to hashlib name (e.g. 'SHA-256' → 'sha256')."""
    return algorithm.lower().replace("-", "")


def _pbkdf2_digest(algorithm: str) -> str:
    """Map PBKDF2 algorithm string to hashlib name (e.g. 'PBKDF2/SHA-256' → 'sha256')."""
    part = algorithm.split("/")[-1]  # 'SHA-256', 'SHA-384', 'SHA-512'
    return part.lower().replace("-", "")


def derive_key_sha(
    parameters: ChallengeParameters, salt: bytes, password: bytes
) -> bytes:
    """
    Iterated SHA key derivation (mirrors the JS sha.ts algorithm).

    Performs ``cost`` iterations of hashing, starting with ``salt + password``,
    then feeding the previous hash into the next round.
    """
    algo = _sha_digest(parameters.algorithm)
    iterations = max(1, parameters.cost)
    data = salt + password
    derived: bytes = b""
    for i in range(iterations):
        if i > 0:
            data = derived
        derived = hashlib.new(algo, data).digest()
    return derived[: parameters.key_length]


def derive_key_pbkdf2(
    parameters: ChallengeParameters, salt: bytes, password: bytes
) -> bytes:
    """PBKDF2 key derivation. Algorithm must be 'PBKDF2/SHA-256', 'PBKDF2/SHA-384', or 'PBKDF2/SHA-512'."""
    digest = _pbkdf2_digest(parameters.algorithm)
    return hashlib.pbkdf2_hmac(
        digest, password, salt, parameters.cost, parameters.key_length
    )


def derive_key_scrypt(
    parameters: ChallengeParameters, salt: bytes, password: bytes
) -> bytes:
    """
    Scrypt key derivation.

    Parameters map as: ``cost`` → N, ``memory_cost`` → r (block size),
    ``parallelism`` → p.
    """
    n = parameters.cost
    r = parameters.memory_cost or 8
    p = parameters.parallelism or 1
    maxmem = 2 * 128 * n * r
    return hashlib.scrypt(
        password, salt=salt, n=n, r=r, p=p, dklen=parameters.key_length, maxmem=maxmem
    )


try:
    from argon2.low_level import Type as _Argon2Type  # type: ignore
    from argon2.low_level import hash_secret_raw as _argon2_hash_secret_raw  # type: ignore

    def derive_key_argon2id(
        parameters: ChallengeParameters, salt: bytes, password: bytes
    ) -> bytes:
        """Argon2id key derivation. Requires the ``argon2-cffi`` package."""
        return _argon2_hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=parameters.cost,
            memory_cost=parameters.memory_cost or 65536,
            parallelism=parameters.parallelism or 1,
            hash_len=parameters.key_length,
            type=_Argon2Type.ID,
        )

except ImportError:

    def derive_key_argon2id(  # type: ignore[misc]
        parameters: ChallengeParameters, salt: bytes, password: bytes
    ) -> bytes:
        """Argon2id key derivation (unavailable — install ``argon2-cffi``)."""
        raise ImportError(
            "argon2-cffi is required for Argon2id. Install with: pip install argon2-cffi"
        )


def _select_derive_key(algorithm: str) -> DeriveKeyFunctionV2:
    """Return the appropriate built-in derive_key function for the given algorithm string."""
    alg = algorithm.upper()
    if alg.startswith("PBKDF2"):
        return derive_key_pbkdf2
    if alg == "ARGON2ID":
        return derive_key_argon2id
    if alg == "SCRYPT":
        return derive_key_scrypt
    # Fallback: plain iterated SHA (algorithm is e.g. 'SHA-256')
    return derive_key_sha


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_challenge(
    algorithm: str,
    cost: int,
    *,
    derive_key: DeriveKeyFunctionV2 | None = None,
    counter: int | None = None,
    key_length: int = DEFAULT_KEY_LENGTH,
    key_prefix: str = DEFAULT_KEY_PREFIX,
    key_prefix_length: int | None = None,
    memory_cost: int | None = None,
    parallelism: int | None = None,
    expires_at: int | datetime.datetime | None = None,
    data: dict | None = None,
    hmac_secret: str | None = None,
    hmac_key_secret: str | None = None,
    hmac_algorithm: HmacAlgorithmV2 = DEFAULT_HMAC_ALGORITHM,
) -> Challenge:
    """
    Create a new v2 proof-of-work challenge.

    Args:
        algorithm: KDF algorithm identifier (e.g. ``'PBKDF2/SHA-256'``, ``'ARGON2ID'``, ``'SCRYPT'``).
        cost: Algorithm-specific cost parameter (iterations, passes, …).
        derive_key: KDF function ``(parameters, salt, password) -> bytes``.
            Defaults to the built-in function selected by *algorithm*.
        counter: If given, pre-solve with this counter and embed the resulting key prefix
            so the client must find this exact counter (deterministic mode).
        key_length: Derived key length in bytes. Defaults to 32.
        key_prefix: Hex prefix the derived key must start with. Defaults to ``'00'``.
        key_prefix_length: Bytes of the derived key used as prefix in deterministic mode.
            Defaults to ``key_length // 2``.
        memory_cost: Memory cost in KiB (Argon2id / scrypt).
        parallelism: Parallelism factor (Argon2id / scrypt).
        expires_at: Expiry as a Unix timestamp (int) or ``datetime``.
        data: Arbitrary metadata to embed in the challenge parameters.
        hmac_secret: Secret used to HMAC-sign the challenge parameters.
            If omitted, the challenge is unsigned.
        hmac_key_secret: If set, also HMAC the derived key for fast verification.
        hmac_algorithm: HMAC digest algorithm. Defaults to ``'SHA-256'``.

    Returns:
        A :class:`Challenge` instance.
    """
    if derive_key is None:
        derive_key = _select_derive_key(algorithm)

    if key_prefix_length is None:
        key_prefix_length = key_length // 2

    expires_at_ts: int | None = None
    if expires_at is not None:
        if isinstance(expires_at, datetime.datetime):
            expires_at_ts = int(expires_at.timestamp())
        else:
            expires_at_ts = int(expires_at)

    nonce = secrets.token_bytes(16).hex()
    salt = secrets.token_bytes(16).hex()

    parameters = ChallengeParameters(
        algorithm=algorithm,
        nonce=nonce,
        salt=salt,
        cost=cost,
        key_length=key_length,
        key_prefix=key_prefix,
        memory_cost=memory_cost,
        parallelism=parallelism,
        expires_at=expires_at_ts,
        data=data,
    )

    derived_key_bytes: bytes | None = None
    if counter is not None:
        nonce_bytes = bytes.fromhex(nonce)
        salt_bytes = bytes.fromhex(salt)
        password = _make_password(nonce_bytes, counter)
        derived_key_bytes = derive_key(parameters, salt_bytes, password)
        parameters.key_prefix = derived_key_bytes[:key_prefix_length].hex()

    if hmac_secret is None:
        return Challenge(parameters=parameters, signature=None)

    return _sign_challenge_v2(
        hmac_algorithm, parameters, derived_key_bytes, hmac_secret, hmac_key_secret
    )


def solve_challenge(
    challenge: Challenge,
    derive_key: DeriveKeyFunctionV2 | None = None,
    *,
    counter_start: int = 0,
    counter_step: int = 1,
    timeout: float = 90.0,
) -> Solution | None:
    """
    Solve a v2 challenge by brute-forcing counter values.

    Args:
        challenge: The challenge to solve.
        derive_key: KDF function. Defaults to the built-in selected by the challenge algorithm.
        counter_start: First counter value to try.
        counter_step: Increment between attempts. Use > 1 for parallel partitioning.
        timeout: Maximum seconds to spend. Returns ``None`` on timeout.

    Returns:
        A :class:`Solution` on success, or ``None`` if no solution was found in time.
    """
    params = challenge.parameters
    if derive_key is None:
        derive_key = _select_derive_key(params.algorithm)

    nonce_bytes = bytes.fromhex(params.nonce)
    salt_bytes = bytes.fromhex(params.salt)

    key_prefix = params.key_prefix
    prefix_bytes: bytes | None = (
        bytes.fromhex(key_prefix) if len(key_prefix) % 2 == 0 else None
    )

    start_time = time.monotonic()
    counter = counter_start

    while True:
        if counter % 10 == 0 and timeout and (time.monotonic() - start_time) > timeout:
            return None

        password = _make_password(nonce_bytes, counter)
        derived_key = derive_key(params, salt_bytes, password)

        matched = (
            _buffer_starts_with(derived_key, prefix_bytes)
            if prefix_bytes is not None
            else derived_key.hex().startswith(key_prefix)
        )

        if matched:
            return Solution(
                counter=counter,
                derived_key=derived_key.hex(),
                time=(time.monotonic() - start_time) * 1000,
            )

        counter += counter_step


def verify_solution(
    payload: str | Payload,
    hmac_secret: str,
    derive_key: DeriveKeyFunctionV2 | None = None,
    *,
    hmac_key_secret: str | None = None,
    hmac_algorithm: HmacAlgorithmV2 = DEFAULT_HMAC_ALGORITHM,
) -> VerifySolutionResult:
    """
    Verify a v2 challenge solution.

    Checks (in order):

    1. Whether the challenge has expired.
    2. Whether the challenge signature is present.
    3. Whether the challenge signature is valid (tamper check).
    4. Whether the solution is correct — via key signature (fast) or re-derivation (slow).

    Args:
        payload: Base64-encoded JSON payload string or a :class:`Payload` object.
        hmac_secret: Secret used to verify the challenge signature.
        derive_key: KDF function for re-derivation. Defaults to built-in for the algorithm.
        hmac_key_secret: Secret used to verify the derived-key signature (fast path).
        hmac_algorithm: HMAC digest algorithm. Defaults to ``'SHA-256'``.

    Returns:
        A :class:`VerifySolutionResult` describing the outcome.
    """
    start_time = time.monotonic()

    challenge: Challenge
    solution: Solution

    if isinstance(payload, str):
        try:
            d = json.loads(base64.b64decode(payload).decode())
            challenge = Challenge.from_dict(d["challenge"])
            solution = Solution.from_dict(d["solution"])
        except (ValueError, KeyError, TypeError):
            return VerifySolutionResult(
                expired=False,
                invalid_signature=None,
                invalid_solution=None,
                time=(time.monotonic() - start_time) * 1000,
                verified=False,
                error="Invalid altcha payload",
            )
    else:
        challenge = payload.challenge
        solution = payload.solution

    # 1. Expiration check.
    if (
        challenge.parameters.expires_at
        and challenge.parameters.expires_at < time.time()
    ):
        return VerifySolutionResult(
            expired=True,
            invalid_signature=None,
            invalid_solution=None,
            time=(time.monotonic() - start_time) * 1000,
            verified=False,
        )

    # 2. Signature must be present.
    if not challenge.signature:
        return VerifySolutionResult(
            expired=False,
            invalid_signature=True,
            invalid_solution=None,
            time=(time.monotonic() - start_time) * 1000,
            verified=False,
        )

    # 3. Verify challenge signature (tamper check).
    params_dict = challenge.parameters.to_dict()
    canonical = _canonical_json(params_dict)
    expected_sig = _hmac_v2(hmac_algorithm, canonical, hmac_secret).hex()
    if not _constant_time_equal(challenge.signature, expected_sig):
        return VerifySolutionResult(
            expired=False,
            invalid_signature=True,
            invalid_solution=None,
            time=(time.monotonic() - start_time) * 1000,
            verified=False,
        )

    params = challenge.parameters

    # 4a. Fast path: verify derived key via its HMAC signature.
    if params.key_signature and hmac_key_secret:
        derived_key_bytes = bytes.fromhex(solution.derived_key)
        expected_key_sig = _hmac_v2(
            hmac_algorithm, derived_key_bytes, hmac_key_secret
        ).hex()
        valid = _constant_time_equal(params.key_signature, expected_key_sig)
        return VerifySolutionResult(
            expired=False,
            invalid_signature=False,
            invalid_solution=not valid,
            time=(time.monotonic() - start_time) * 1000,
            verified=valid,
        )

    # 4b. Slow path: re-derive the key from the counter and compare.
    if derive_key is None:
        derive_key = _select_derive_key(params.algorithm)

    nonce_bytes = bytes.fromhex(params.nonce)
    salt_bytes = bytes.fromhex(params.salt)
    password = _make_password(nonce_bytes, solution.counter)
    recomputed = derive_key(params, salt_bytes, password)
    recomputed_hex = recomputed.hex()
    invalid = not _constant_time_equal(recomputed_hex, solution.derived_key)

    return VerifySolutionResult(
        expired=False,
        invalid_signature=False,
        invalid_solution=invalid,
        time=(time.monotonic() - start_time) * 1000,
        verified=not invalid,
    )


# ---------------------------------------------------------------------------
# Server signature verification
# ---------------------------------------------------------------------------

#: Fields whose comma-separated value is automatically split into a list.
_ARRAY_FIELDS = ("fields", "reasons")


class ServerSignaturePayload:
    """
    A server-signed verification payload (as returned by the ALTCHA API).

    Attributes:
        algorithm: HMAC/hash algorithm (e.g. ``'SHA-256'``).
        signature: HMAC signature of the hashed verification data.
        verification_data: URL-encoded query string of verification attributes.
        verified: Whether the server marked the payload as verified.
    """

    def __init__(
        self,
        algorithm: str,
        signature: str,
        verification_data: str,
        verified: bool,
    ):
        self.algorithm = algorithm
        self.signature = signature
        self.verification_data = verification_data
        self.verified = verified

    @classmethod
    def from_dict(cls, d: dict) -> ServerSignaturePayload:
        return cls(
            algorithm=d["algorithm"],
            signature=d["signature"],
            verification_data=d["verificationData"],
            verified=bool(d.get("verified", False)),
        )

    @classmethod
    def from_base64(cls, data: str) -> ServerSignaturePayload:
        return cls.from_dict(json.loads(base64.b64decode(data).decode()))


class VerifyServerSignatureResult:
    """
    Result of a server signature verification.

    Attributes:
        expired: ``True`` if the ``expire`` field is in the past.
        invalid_signature: ``True`` if the HMAC signature does not match.
        invalid_solution: ``True`` if ``verified`` is not ``True`` in the payload
            or in the parsed verification data.
        time: Time taken for verification in milliseconds.
        verified: ``True`` if all checks passed.
        verification_data: Parsed key/value data from the verification string,
            or ``None`` if parsing failed.
    """

    def __init__(
        self,
        expired: bool,
        invalid_signature: bool,
        invalid_solution: bool,
        time: float,
        verified: bool,
        verification_data: dict | None,
    ):
        self.expired = expired
        self.invalid_signature = invalid_signature
        self.invalid_solution = invalid_solution
        self.time = time
        self.verified = verified
        self.verification_data = verification_data


def parse_verification_data(
    data: str,
    convert_to_array: tuple[str, ...] = _ARRAY_FIELDS,
) -> dict | None:
    """
    Parse URL-encoded verification data into a typed dict.

    Values are coerced as follows:

    - ``'true'`` / ``'false'`` → ``bool``
    - All-digit strings → ``int``
    - Digit-dot-digit strings → ``float``
    - Keys in *convert_to_array* → ``list[str]`` (comma-split)
    - Everything else → ``str``

    Returns ``None`` if parsing fails.
    """
    try:
        result: dict = {}
        for key, value in urllib.parse.parse_qsl(data):
            if value == "true":
                result[key] = True
            elif value == "false":
                result[key] = False
            elif re.fullmatch(r"\d+", value):
                result[key] = int(value)
            elif re.fullmatch(r"\d+\.\d+", value):
                result[key] = float(value)
            elif key in convert_to_array and value:
                result[key] = [v.strip() for v in value.split(",")]
            else:
                result[key] = value.strip()
        return result
    except Exception:
        return None


def verify_server_signature(
    payload: str | ServerSignaturePayload,
    hmac_secret: str,
    *,
    hmac_algorithm: HmacAlgorithmV2 = DEFAULT_HMAC_ALGORITHM,
) -> VerifyServerSignatureResult:
    """
    Verify an ALTCHA server-signed payload.

    Args:
        payload: Base64-encoded JSON string or a :class:`ServerSignaturePayload` object.
        hmac_secret: Secret used to verify the HMAC signature.
        hmac_algorithm: HMAC digest algorithm. Defaults to ``'SHA-256'``.

    Returns:
        A :class:`VerifyServerSignatureResult` describing the outcome.
    """
    start_time = time.monotonic()

    if isinstance(payload, str):
        try:
            p = ServerSignaturePayload.from_base64(payload)
        except (ValueError, KeyError, TypeError):
            return VerifyServerSignatureResult(
                expired=False,
                invalid_signature=True,
                invalid_solution=True,
                time=(time.monotonic() - start_time) * 1000,
                verified=False,
                verification_data=None,
            )
    else:
        p = payload

    # Compute expected signature: HMAC(hash(verificationData), secret)
    hash_name = p.algorithm.lower().replace("-", "")
    data_hash = hashlib.new(hash_name, p.verification_data.encode()).digest()
    expected_sig = _hmac_v2(hmac_algorithm, data_hash, hmac_secret).hex()

    verification_data = parse_verification_data(p.verification_data)

    expire = verification_data.get("expire") if verification_data else None
    expired = isinstance(expire, int) and expire < int(time.time())

    invalid_signature = not _constant_time_equal(p.signature, expected_sig)

    invalid_solution = (
        verification_data is None
        or verification_data.get("verified") is not True
        or not p.verified
    )

    verified = not expired and not invalid_signature and not invalid_solution

    return VerifyServerSignatureResult(
        expired=expired,
        invalid_signature=invalid_signature,
        invalid_solution=invalid_solution,
        time=(time.monotonic() - start_time) * 1000,
        verified=verified,
        verification_data=verification_data if verified else None,
    )
