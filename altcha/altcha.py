"""
Backward-compatibility shim.

Imports the v1 API under its original names so that existing code importing
from ``altcha.altcha`` continues to work unchanged.
"""

from .v1 import (
    DEFAULT_ALGORITHM as DEFAULT_ALGORITHM,
    DEFAULT_MAX_NUMBER as DEFAULT_MAX_NUMBER,
    DEFAULT_SALT_LENGTH as DEFAULT_SALT_LENGTH,
    SHA1 as SHA1,
    SHA256 as SHA256,
    SHA512 as SHA512,
    AlgoType as AlgoType,
    Challenge as Challenge,
    ChallengeOptions as ChallengeOptions,
    Payload as Payload,
    PayloadType as PayloadType,
    ServerSignaturePayload as ServerSignaturePayload,
    ServerSignatureVerificationData as ServerSignatureVerificationData,
    Solution as Solution,
    create_challenge as create_challenge,
    extract_params as extract_params,
    hash_algorithm as hash_algorithm,
    hash_hex as hash_hex,
    hmac_hex as hmac_hex,
    solve_challenge as solve_challenge,
    verify_fields_hash as verify_fields_hash,
    verify_server_signature as verify_server_signature,
    verify_solution as verify_solution,
)
