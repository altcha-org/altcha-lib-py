from __future__ import annotations

import hashlib
import hmac
import base64
import json
import secrets
import time
import urllib.parse
from typing import Literal, TypedDict, cast, overload
import datetime

# Define algorithms
SHA1: Literal["SHA-1"] = "SHA-1"
SHA256: Literal["SHA-256"] = "SHA-256"
SHA512: Literal["SHA-512"] = "SHA-512"

AlgoType = Literal["SHA-1", "SHA-256", "SHA-512"]


class PayloadType(TypedDict, total=False):
    algorithm: AlgoType
    challenge: str
    number: int
    salt: str
    signature: str
    verificationData: str
    verified: bool


DEFAULT_MAX_NUMBER: int = int(1e6)  # Default maximum number for challenge
DEFAULT_SALT_LENGTH: int = 12  # Default length of salt in bytes
DEFAULT_ALGORITHM: AlgoType = SHA256  # Default hashing algorithm


class ChallengeOptions:
    """
    Represents options for creating a challenge.

    Attributes:
        algorithm (str): Hashing algorithm to use (e.g., 'SHA-1', 'SHA-256', 'SHA-512').
        max_number (int): Maximum number to use for the challenge.
        salt_length (int): Length of the salt in bytes.
        hmac_key (str): HMAC key for generating the signature.
        salt (str): Optional salt value. If not provided, a random salt is generated.
        number (int): Optional number for the challenge. If not provided, a random number is used.
        expires (datetime): Optional expiration time for the challenge.
        params (dict): Optional additional parameters to include in the challenge.
    """

    def __init__(
        self,
        algorithm: AlgoType = DEFAULT_ALGORITHM,
        max_number: int = DEFAULT_MAX_NUMBER,
        salt_length: int = DEFAULT_SALT_LENGTH,
        hmac_key: str = "",
        salt: str = "",
        number: int | None = None,
        expires: datetime.datetime | None = None,
        params: dict[str, str] | None = None,
    ):
        self.algorithm = algorithm
        self.max_number = max_number
        self.salt_length = salt_length
        self.hmac_key = hmac_key
        self.salt = salt
        self.number = number
        self.expires = expires
        self.params = params if params else {}


class Challenge:
    """
    Represents a generated challenge.

    Attributes:
        algorithm (str): Hashing algorithm used.
        challenge (str): Challenge string.
        max_number (int): Maximum number used for the challenge.
        salt (str): Salt used for generating the challenge.
        signature (str): HMAC signature for the challenge.
    """

    def __init__(
        self,
        algorithm: AlgoType,
        challenge: str,
        max_number: int,
        salt: str,
        signature: str,
    ):
        self.algorithm = algorithm
        self.challenge = challenge
        self.max_number = max_number
        self.salt = salt
        self.signature = signature

    def to_dict(self) -> dict:
        """Convert the Challenge to a dictionary."""
        return {
            "algorithm": self.algorithm,
            "challenge": self.challenge,
            "maxNumber": self.max_number,
            "salt": self.salt,
            "signature": self.signature,
        }


class Payload:
    """
    Represents the payload of a challenge solution.

    Attributes:
        algorithm (str): Hashing algorithm used.
        challenge (str): Challenge string.
        number (int): Number used in the solution.
        salt (str): Salt used in the solution.
        signature (str): HMAC signature of the solution.
    """

    def __init__(
        self,
        algorithm: AlgoType,
        challenge: str,
        number: int,
        salt: str,
        signature: str,
    ):
        self.algorithm = algorithm
        self.challenge = challenge
        self.number = number
        self.salt = salt
        self.signature = signature

    def to_dict(self) -> PayloadType:
        """Convert the Payload to a dictionary."""
        return {
            "algorithm": self.algorithm,
            "challenge": self.challenge,
            "number": self.number,
            "salt": self.salt,
            "signature": self.signature,
        }

    def to_base64(self) -> str:
        """Convert the Payload to a base64 encoded JSON string."""
        return base64.b64encode(json.dumps(self.to_dict()).encode()).decode()


class ServerSignaturePayload:
    """
    Represents the payload for server signature verification.

    Attributes:
        algorithm (str): Hashing algorithm used.
        apiKey (str): API Key used for signature.
        id (str): Unique signature id.
        verificationData (str): Data used for verification.
        signature (str): HMAC signature of the verification data.
        verified (bool): Whether the signature was verified.
    """

    def __init__(
        self,
        algorithm: AlgoType,
        apiKey: str,
        id: str,
        verificationData: str,
        signature: str,
        verified: bool,
    ):
        self.algorithm = algorithm
        self.apiKey = apiKey
        self.id = id
        self.verificationData = verificationData
        self.signature = signature
        self.verified = verified

    def to_dict(self) -> dict:
        """Convert the ServerSignaturePayload to a dictionary."""
        return {
            "algorithm": self.algorithm,
            "apiKey": self.apiKey,
            "id": self.id,
            "verificationData": self.verificationData,
            "signature": self.signature,
            "verified": self.verified,
        }

    def to_base64(self) -> str:
        """Convert the ServerSignaturePayload to a base64 encoded JSON string."""
        return base64.b64encode(json.dumps(self.to_dict()).encode()).decode()


class ServerSignatureVerificationData:
    """
    Represents verification data for server signatures with support for custom string:string attributes.

    Attributes:
        classification (str): The classification of the verification
        country (str): [DEPRECATED] Use "location.countryCode" instead with Sentinel.
        detectedLanguage (str): [DEPRECATED] Use "text.language" instead with Sentinel.
        email (str): The associated email
        expire (int): Expiration timestamp
        fields (list[str]): List of fields
        fieldsHash (str): Hash of the fields
        ipAddress (str): The IP address
        reasons (list[str]): List of reasons
        score (float): Verification score
        time (int): Timestamp
        verified (bool): Verification status
    """

    def __init__(
        self,
        classification: str = "",
        country: str = "",
        detected_language: str = "",
        email: str = "",
        expire: int = 0,
        fields: list[str] | None = None,
        fields_hash: str = "",
        ip_address: str = "",
        reasons: list[str] | None = None,
        score: float = 0.0,
        time: int = 0,
        verified: bool = False,
        **custom: str,
    ):
        self.classification = classification
        self.country = country
        self.detectedLanguage = detected_language
        self.email = email
        self.expire = expire
        self.fields = fields if fields else []
        self.fieldsHash = fields_hash
        self.ipAddress = ip_address
        self.reasons = reasons if reasons else []
        self.score = score
        self.time = time
        self.verified = verified

        # Store any extra custom attributes (must be str:str)
        for key, value in custom.items():
            if not isinstance(value, str):
                raise TypeError(f"Custom attribute '{key}' must be of type str")
            setattr(self, key, value)

    def to_dict(self) -> dict:
        """
        Converts the ServerSignatureVerificationData object to a dictionary.

        Returns:
            A dictionary containing all the standard and custom attributes.
        """
        # Standard attributes
        data = {
            "classification": self.classification,
            "country": self.country,
            "detectedLanguage": self.detectedLanguage,
            "email": self.email,
            "expire": self.expire,
            "fields": self.fields.copy(),
            "fieldsHash": self.fieldsHash,
            "ipAddress": self.ipAddress,
            "reasons": self.reasons.copy(),
            "score": self.score,
            "time": self.time,
            "verified": self.verified,
        }

        # Add custom attributes
        for key, value in self.__dict__.items():
            if key not in data and isinstance(value, str):
                data[key] = value

        return data


class Solution:
    """
    Represents a solution to a challenge.

    Attributes:
        number (int): Number that solved the challenge.
        took (float): Time taken to solve the challenge, in seconds.
    """

    def __init__(self, number: int, took: float):
        self.number = number
        self.took = took


def hash_hex(algorithm: AlgoType, data: bytes) -> str:
    """
    Computes the hexadecimal digest of the given data using the specified hashing algorithm.

    Args:
        algorithm (str): Hashing algorithm to use (e.g., 'SHA-1', 'SHA-256', 'SHA-512').
        data (bytes): Data to hash.

    Returns:
        str: Hexadecimal digest of the data.
    """
    hash_obj = hash_algorithm(algorithm)
    hash_obj.update(data)
    return hash_obj.hexdigest()


def hash_algorithm(algorithm: AlgoType) -> hashlib._Hash:
    """
    Returns a hash object for the specified hashing algorithm.

    Args:
        algorithm (str): Hashing algorithm to use (e.g., 'SHA-1', 'SHA-256', 'SHA-512').

    Returns:
        hashlib.Hash: Hash object for the specified algorithm.

    Raises:
        ValueError: If the algorithm is unsupported.
    """
    if algorithm == SHA1:
        return hashlib.sha1()
    elif algorithm == SHA256:
        return hashlib.sha256()
    elif algorithm == SHA512:
        return hashlib.sha512()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def hmac_hex(algorithm: AlgoType, data: bytes, key: str) -> str:
    """
    Computes the HMAC hexadecimal digest of the given data using the specified algorithm and key.

    Args:
        algorithm (str): Hashing algorithm to use (e.g., 'SHA-1', 'SHA-256', 'SHA-512').
        data (bytes): Data to HMAC.
        key (str): Key for the HMAC.

    Returns:
        str: Hexadecimal HMAC digest of the data.
    """
    hmac_obj = hmac.new(
        key.encode(), data, getattr(hashlib, algorithm.replace("-", "").lower())
    )
    return hmac_obj.hexdigest()


@overload
def create_challenge(options: ChallengeOptions) -> Challenge: ...
@overload
def create_challenge(
    *,
    algorithm: AlgoType,
    max_number: int,
    salt_length: int,
    hmac_key: str,
    salt: str,
    number: int | None,
    expires: datetime.datetime | None,
    params: dict[str, str] | None,
) -> Challenge: ...


def create_challenge(
    options: ChallengeOptions | None = None,
    *,
    algorithm: AlgoType = DEFAULT_ALGORITHM,
    max_number: int = DEFAULT_MAX_NUMBER,
    salt_length: int = DEFAULT_SALT_LENGTH,
    hmac_key: str = "",
    salt: str = "",
    number: int | None = None,
    expires: datetime.datetime | None = None,
    params: dict[str, str] | None = None,
) -> Challenge:
    """
    Creates a challenge based on the provided options.

    Args:
        options (ChallengeOptions): Options for creating the challenge.
        or individual parameters:
        algorithm (str): Hashing algorithm to use.
        max_number (int): Maximum number to use.
        salt_length (int): Length of the salt in bytes.
        hmac_key (str): HMAC key for generating the signature.
        salt (str): Optional salt value.
        number (int): Optional number for the challenge.
        expires (datetime): Optional expiration time.
        params (dict): Optional additional parameters.

    Returns:
        Challenge: The generated challenge.
    """
    if options is None:
        options = ChallengeOptions(
            algorithm=algorithm,
            max_number=max_number,
            salt_length=salt_length,
            hmac_key=hmac_key,
            salt=salt,
            number=number,
            expires=expires,
            params=params,
        )

    algorithm = options.algorithm or DEFAULT_ALGORITHM
    max_number = options.max_number or DEFAULT_MAX_NUMBER
    salt_length = options.salt_length or DEFAULT_SALT_LENGTH

    salt = (
        options.salt
        or base64.b16encode(secrets.token_bytes(salt_length)).decode("utf-8").lower()
    )
    number = (
        options.number
        if options.number is not None
        else secrets.randbelow(max_number + 1)
    )

    salt_params = {}
    if "?" in salt:
        salt, salt_query = salt.split("?", 2)
        salt_params = dict(urllib.parse.parse_qsl(salt_query))

    if options.expires:
        expires = options.expires

        if expires.tzinfo is None:
            # Backward compatibility: assume naive datetimes are local time
            timestamp = int(time.mktime(expires.timetuple()))
        else:
            # Aware datetimes: use true UTC timestamp
            timestamp = int(expires.timestamp())

        salt_params["expires"] = str(timestamp)

    if options.params:
        salt_params.update(options.params)

    if salt_params:
        salt += "?" + urllib.parse.urlencode(salt_params)

    # Add a delimiter to prevent parameter splicing
    if not salt.endswith("&"):
        salt += "&"

    challenge = hash_hex(algorithm, (salt + str(number)).encode())
    signature = hmac_hex(algorithm, challenge.encode(), options.hmac_key)

    return Challenge(algorithm, challenge, max_number, salt, signature)


@overload
def verify_solution(
    payload: Payload,
    hmac_key: str,
    check_expires: bool = True,
) -> tuple[bool, str | None]: ...
@overload
def verify_solution(
    payload: str,
    hmac_key: str,
    check_expires: bool = True,
) -> tuple[bool, str | None]: ...
@overload
def verify_solution(
    payload: PayloadType,
    hmac_key: str,
    check_expires: bool = True,
) -> tuple[bool, str | None]: ...


def verify_solution(
    payload: str | Payload | PayloadType,
    hmac_key: str,
    check_expires: bool = True,
) -> tuple[bool, str | None]:
    """
    Verifies a challenge solution against the expected challenge.

    Args:
        payload (str | Payload | PayloadType): The solution payload to verify.
        hmac_key (str): HMAC key for verifying the solution.
        check_expires (bool): Whether to check the expiration time.

    Returns:
        tuple: (bool: verification success, str | None: error message if any)
    """
    payload_dict: PayloadType
    if isinstance(payload, Payload):
        payload_dict = payload.to_dict()
    elif isinstance(payload, str):
        try:
            payload_dict = cast(
                PayloadType, json.loads(base64.b64decode(payload).decode())
            )
        except (ValueError, TypeError):
            return False, "Invalid altcha payload"
    else:
        payload_dict = payload

    required_fields = ["algorithm", "challenge", "number", "salt", "signature"]
    for field in required_fields:
        if field not in payload_dict:
            return False, f"Missing required field: {field}"

    if payload_dict["algorithm"] not in ["SHA-1", "SHA-256", "SHA-512"]:
        return False, "Invalid algorithm"

    expires = extract_params(payload_dict).get("expires")
    try:
        if check_expires and expires and int(expires[0]) < time.time():
            return False, "Altcha payload expired"
    except ValueError:  # Guard against malformed expires
        return False, "Altcha payload expired"

    options = ChallengeOptions(
        algorithm=payload_dict["algorithm"],
        hmac_key=hmac_key,
        number=payload_dict["number"],
        salt=payload_dict["salt"],
    )
    expected_challenge = create_challenge(options)

    return (
        expected_challenge.challenge == payload_dict["challenge"]
        and expected_challenge.signature == payload_dict["signature"]
    ), None


def extract_params(payload: PayloadType) -> dict[str, list[str]]:
    """
    Extracts query parameters from the salt string in the payload.

    Args:
        payload (dict): Payload containing the salt.

    Returns:
        dict: Dictionary of query parameters extracted from the salt.
    """
    split_salt = payload["salt"].split("?")
    if len(split_salt) > 1:
        return urllib.parse.parse_qs(split_salt[1])
    return {}


def verify_fields_hash(
    form_data: dict[str, str], fields: list[str], fields_hash: str, algorithm: AlgoType
) -> bool:
    """
    Verifies that the hash of specific form fields matches the expected hash.

    Args:
        form_data (dict): Form data containing the fields to hash.
        fields (list): List of field names to include in the hash.
        fields_hash (str): Expected hash of the fields.
        algorithm (str): Hashing algorithm to use (e.g., 'SHA-1', 'SHA-256', 'SHA-512').

    Returns:
        bool: True if the computed hash matches the expected hash, False otherwise.
    """
    lines = [form_data.get(field, "") for field in fields]
    joined_data = "\n".join(lines)
    computed_hash = hash_hex(algorithm, joined_data.encode())
    return computed_hash == fields_hash


@overload
def verify_server_signature(
    payload: str,
    hmac_key: str,
) -> tuple[bool, ServerSignatureVerificationData | None, str | None]: ...
@overload
def verify_server_signature(
    payload: ServerSignaturePayload,
    hmac_key: str,
) -> tuple[bool, ServerSignatureVerificationData | None, str | None]: ...
@overload
def verify_server_signature(
    payload: PayloadType,
    hmac_key: str,
) -> tuple[bool, ServerSignatureVerificationData | None, str | None]: ...


def verify_server_signature(
    payload: str | ServerSignaturePayload | PayloadType,
    hmac_key: str,
) -> tuple[bool, ServerSignatureVerificationData | None, str | None]:
    """
    Verifies the server signature in the payload.

    Args:
        payload: The payload containing the server signature.
        hmac_key: HMAC key for verifying the signature.

    Returns:
        tuple: (bool: verification success,
                ServerSignatureVerificationData | None: verification data if successful,
                str | None: error message if any)
    """
    payload_dict: PayloadType
    if isinstance(payload, ServerSignaturePayload):
        payload_dict = cast(PayloadType, payload.to_dict())
    elif isinstance(payload, str):
        try:
            payload_dict = cast(
                PayloadType, json.loads(base64.b64decode(payload).decode())
            )
        except (ValueError, TypeError):
            return False, None, "Invalid altcha payload"
    else:
        payload_dict = payload

    required_fields = ["algorithm", "verificationData", "signature", "verified"]
    for field in required_fields:
        if field not in payload_dict:
            return False, None, "Invalid altcha payload"

    algorithm = payload_dict["algorithm"]
    verification_data = payload_dict["verificationData"]
    signature = payload_dict["signature"]
    verified = payload_dict["verified"]

    if algorithm not in ["SHA-1", "SHA-256", "SHA-512"]:
        return False, None, "Invalid algorithm"

    hash_obj = hash_algorithm(algorithm)
    hash_obj.update(verification_data.encode())
    expected_signature = hmac_hex(algorithm, hash_obj.digest(), hmac_key)
    now = int(time.time())
    params = urllib.parse.parse_qs(verification_data)
    expire = int(params.get("expire", [0])[0])
    if expire <= now:
        return False, None, "Altcha payload expired"

    is_valid = (signature == expected_signature) and verified
    known_keys = {
        "classification",
        "country",
        "detectedLanguage",
        "email",
        "expire",
        "fields",
        "fieldsHash",
        "reasons",
        "score",
        "time",
        "verified",
    }

    data = ServerSignatureVerificationData(
        classification=params.get("classification", [""])[0],
        country=params.get("country", [""])[0],
        detected_language=params.get("detectedLanguage", [""])[0],
        email=params.get("email", [""])[0],
        expire=expire,
        fields=params.get("fields", [""])[0].split(","),
        fields_hash=params.get("fieldsHash", [""])[0],
        reasons=params.get("reasons", [""])[0].split(","),
        score=float(params.get("score", ["0"])[0]),
        time=int(params.get("time", ["0"])[0]),
        verified=verified,
    )

    for key, value in params.items():
        if key not in known_keys:
            setattr(data, key, value[0])

    return is_valid, data if is_valid else None, None


@overload
def solve_challenge(
    challenge: Challenge,
    salt: str = "",
    algorithm: AlgoType = "SHA-256",
    max_number: int = 1000000,
    start: int = 0,
) -> Solution | None: ...
@overload
def solve_challenge(
    challenge: str,
    salt: str,
    algorithm: AlgoType,
    max_number: int,
    start: int = 0,
) -> Solution | None: ...


def solve_challenge(
    challenge: Challenge | str,
    salt: str = "",
    algorithm: AlgoType = "SHA-256",
    max_number: int = 1000000,
    start: int = 0,
) -> Solution | None:
    """
    Attempts to solve a challenge by finding a number that matches the challenge hash.
    Args:
        challenge: Either a Challenge object or the challenge string.
        salt: Salt used in the challenge (only needed if challenge is a string).
        algorithm: Hashing algorithm (only needed if challenge is a string).
        max_number: Maximum number to try (only needed if challenge is a string).
        start: Starting number to try.
    Returns:
        Solution: If the challenge is solved.
        None: If no solution is found within the range.
    """
    if isinstance(challenge, Challenge):
        salt = challenge.salt
        algorithm = challenge.algorithm
        max_number = challenge.max_number
        challenge_str = challenge.challenge
    else:
        if not salt:
            raise ValueError(
                "Missing required salt parameter when challenge is a string"
            )
        if not algorithm:
            algorithm = "SHA-256"
        if max_number <= 0:
            max_number = 1000000
        challenge_str = challenge

    if start < 0:
        start = 0

    start_time = time.time()
    for n in range(start, max_number + 1):
        hash_hex_value = hash_hex(algorithm, (salt + str(n)).encode())
        if hash_hex_value == challenge_str:
            took = time.time() - start_time
            return Solution(n, took)

    return None
