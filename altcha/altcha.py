import hashlib
import hmac
import base64
import json
import secrets
import time
import urllib.parse

# Define algorithms
SHA1 = "SHA-1"
SHA256 = "SHA-256"
SHA512 = "SHA-512"

DEFAULT_MAX_NUMBER = int(1e6)  # Default maximum number for challenge
DEFAULT_SALT_LENGTH = 12  # Default length of salt in bytes
DEFAULT_ALGORITHM = SHA256  # Default hashing algorithm


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
        algorithm=DEFAULT_ALGORITHM,
        max_number=DEFAULT_MAX_NUMBER,
        salt_length=DEFAULT_SALT_LENGTH,
        hmac_key="",
        salt="",
        number=0,
        expires=None,
        params=None,
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

    def __init__(self, algorithm, challenge, max_number, salt, signature):
        self.algorithm = algorithm
        self.challenge = challenge
        self.maxnumber = max_number
        self.salt = salt
        self.signature = signature


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

    def __init__(self, algorithm, challenge, number, salt, signature):
        self.algorithm = algorithm
        self.challenge = challenge
        self.number = number
        self.salt = salt
        self.signature = signature


class ServerSignaturePayload:
    """
    Represents the payload for server signature verification.

    Attributes:
        algorithm (str): Hashing algorithm used.
        verificationData (str): Data used for verification.
        signature (str): HMAC signature of the verification data.
        verified (bool): Whether the signature was verified.
    """

    def __init__(self, algorithm, verificationData, signature, verified):
        self.algorithm = algorithm
        self.verificationData = verificationData
        self.signature = signature
        self.verified = verified


class ServerSignatureVerificationData:
    """
    Represents verification data for server signatures.

    Attributes:
        classification (str): Classification of the data.
        country (str): Country associated with the data.
        detectedLanguage (str): Language detected from the data.
        email (str): Email address associated with the data.
        expire (int): Expiration time in seconds since epoch.
        fields (list): List of fields included in the data.
        fieldsHash (str): Hash of the fields.
        ipAddress (str): IP address associated with the data.
        reasons (list): Reasons associated with the data.
        score (float): Score associated with the data.
        time (int): Time associated with the data.
        verified (bool): Whether the data was verified.
    """

    def __init__(
        self,
        classification="",
        country="",
        detected_language="",
        email="",
        expire=0,
        fields=None,
        fields_hash="",
        ip_address="",
        reasons=None,
        score=0.0,
        time=0,
        verified=False,
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


class Solution:
    """
    Represents a solution to a challenge.

    Attributes:
        number (int): Number that solved the challenge.
        took (float): Time taken to solve the challenge, in seconds.
    """

    def __init__(self, number, took):
        self.number = number
        self.took = took


def hash_hex(algorithm, data):
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


def hash_algorithm(algorithm):
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


def hmac_hex(algorithm, data, key):
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


def create_challenge(options):
    """
    Creates a challenge based on the provided options.

    Args:
        options (ChallengeOptions): Options for creating the challenge.

    Returns:
        Challenge: The generated challenge.
    """
    algorithm = options.algorithm or DEFAULT_ALGORITHM
    max_number = options.max_number or DEFAULT_MAX_NUMBER
    salt_length = options.salt_length or DEFAULT_SALT_LENGTH

    salt = (
        options.salt
        or base64.b16encode(secrets.token_bytes(salt_length)).decode("utf-8").lower()
    )
    number = options.number or secrets.randbelow(max_number)

    salt_params = {}
    if "?" in salt:
        salt, salt_query = salt.split("?", 2)
        salt_params = dict(urllib.parse.parse_qsl(salt_query))

    if options.expires:
        salt_params["expires"] = str(int(time.mktime(options.expires.timetuple())))

    if options.params:
        salt_params.update(options.params)

    if salt_params:
        salt += "?" + urllib.parse.urlencode(salt_params)

    challenge = hash_hex(algorithm, (salt + str(number)).encode())
    signature = hmac_hex(algorithm, challenge.encode(), options.hmac_key)

    return Challenge(algorithm, challenge, max_number, salt, signature)


def verify_solution(payload, hmac_key, check_expires):
    """
    Verifies a challenge solution against the expected challenge.

    Args:
        payload (str or dict): Payload containing the solution (base64 encoded JSON string or dictionary).
        hmac_key (str): HMAC key for verifying the solution.
        check_expires (bool): Whether to check the expiration time.

    Returns:
        tuple: A tuple (bool, str or None) where the first element is True if the solution is valid,
               and the second element is an error message or None.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(base64.b64decode(payload).decode())
        except (ValueError, TypeError):
            return False, "Invalid altcha payload"

    required_fields = ["algorithm", "challenge", "number", "salt", "signature"]
    for field in required_fields:
        if field not in payload:
            return False, f"Missing required field: {field}"

    if payload["algorithm"] not in ["SHA-1", "SHA-256", "SHA-512"]:
        return False, "Invalid algorithm"

    expires = extract_params(payload).get("expires")
    try:
        if check_expires and expires and int(expires[0]) < time.time():
            return False, None
    except ValueError:  # Guard against malformed expires
        return False, None

    options = ChallengeOptions(
        algorithm=payload["algorithm"],
        hmac_key=hmac_key,
        number=payload["number"],
        salt=payload["salt"],
    )
    expected_challenge = create_challenge(options)

    return (
        expected_challenge.challenge == payload["challenge"]
        and expected_challenge.signature == payload["signature"]
    ), None


def extract_params(payload):
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


def verify_fields_hash(form_data, fields, fields_hash, algorithm):
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


def verify_server_signature(payload, hmac_key):
    """
    Verifies the server signature in the payload.

    Args:
        payload (str or dict): Payload containing the server signature (base64 encoded JSON string or dictionary).
        hmac_key (str): HMAC key for verifying the signature.

    Returns:
        tuple: A tuple (bool, ServerSignatureVerificationData or None, str or None) where the first element is True if the
               signature is valid, the second element is an instance of ServerSignatureVerificationData containing the
               verification data, and the third element is an error message or None.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(base64.b64decode(payload).decode())
        except (ValueError, TypeError):
            return False, None, "Invalid altcha payload"
    elif not isinstance(payload, dict):
        return False, None, "Invalid altcha payload"

    required_fields = ["algorithm", "verificationData", "signature", "verified"]
    for field in required_fields:
        if field not in payload:
            return False, None, "Invalid altcha payload"

    algorithm = payload["algorithm"]
    verification_data = payload["verificationData"]
    signature = payload["signature"]
    verified = payload["verified"]

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

    return is_valid, data if is_valid else None, None


def solve_challenge(challenge, salt, algorithm, max_number, start):
    """
    Attempts to solve a challenge by finding a number that matches the challenge hash.

    Args:
        challenge (str): Challenge hash to match.
        salt (str): Salt used in the challenge.
        algorithm (str): Hashing algorithm to use (e.g., 'SHA-1', 'SHA-256', 'SHA-512').
        max_number (int): Maximum number to try.
        start (int): Starting number to try.

    Returns:
        Solution: A Solution object containing the number that solves the challenge and the time taken,
                  if the challenge is solved.
        None: If no solution is found within the range.
    """
    if not algorithm:
        algorithm = "SHA-256"
    if max_number <= 0:
        max_number = 1000000
    if start < 0:
        start = 0

    start_time = time.time()

    for n in range(start, max_number + 1):
        hash_hex_value = hash_hex(algorithm, (salt + str(n)).encode())
        if hash_hex_value == challenge:
            took = time.time() - start_time
            return Solution(n, took)

    return None
