"""
Backward-compatibility shim.

Imports the v1 API under its original names so that existing code importing
from ``altcha.altcha`` continues to work unchanged.
"""

from .v1 import (
    AlgoType as AlgoType,
    ChallengeOptions as ChallengeOptions,
    Challenge as Challenge,
    Payload as Payload,
    PayloadType as PayloadType,
    ServerSignaturePayload as ServerSignaturePayload,
    ServerSignatureVerificationData as ServerSignatureVerificationData,
    Solution as Solution,
    DEFAULT_MAX_NUMBER as DEFAULT_MAX_NUMBER,
    DEFAULT_SALT_LENGTH as DEFAULT_SALT_LENGTH,
    DEFAULT_ALGORITHM as DEFAULT_ALGORITHM,
    SHA1 as SHA1,
    SHA256 as SHA256,
    SHA512 as SHA512,
    hash_hex as hash_hex,
    hash_algorithm as hash_algorithm,
    hmac_hex as hmac_hex,
    create_challenge as create_challenge,
    verify_solution as verify_solution,
    extract_params as extract_params,
    verify_fields_hash as verify_fields_hash,
    verify_server_signature as verify_server_signature,
    solve_challenge as solve_challenge,
)
