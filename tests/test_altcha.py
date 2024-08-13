import datetime
import hashlib
import hmac
import time
import unittest
import base64
import json
from altcha.altcha import (
    ChallengeOptions,
    Payload,
    create_challenge,
    hash_algorithm,
    hash_hex,
    hmac_hex,
    solve_challenge,
    verify_server_signature,
    verify_solution,
)


class TestALTCHA(unittest.TestCase):

    def setUp(self):
        self.hmac_key = "test-key"

    def test_create_challenge(self):
        options = ChallengeOptions(
            algorithm="SHA-256",
            max_number=1000,
            salt_length=16,
            hmac_key=self.hmac_key,
            salt="somesalt",
            number=123,
        )
        challenge = create_challenge(options)
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.algorithm, "SHA-256")

    def test_verify_solution_success(self):
        options = ChallengeOptions(
            algorithm="SHA-256",
            max_number=1000,
            salt_length=16,
            hmac_key=self.hmac_key,
            salt="somesalt",
            number=123,
        )
        challenge = create_challenge(options)
        payload = Payload(
            algorithm="SHA-256",
            challenge=challenge.challenge,
            number=123,
            salt="somesalt",
            signature=challenge.signature,
        )
        payload_encoded = base64.b64encode(
            json.dumps(payload.__dict__).encode()
        ).decode()
        result, _ = verify_solution(payload_encoded, self.hmac_key, check_expires=False)
        self.assertTrue(result)

    def test_verify_solution_failure(self):
        options = ChallengeOptions(
            algorithm="SHA-256",
            max_number=1000,
            salt_length=16,
            hmac_key=self.hmac_key,
            salt="somesalt",
            number=123,
        )
        challenge = create_challenge(options)
        payload = Payload(
            algorithm="SHA-256",
            challenge=challenge.challenge,
            number=123,
            salt="somesalt",
            signature="wrong-signature",
        )
        payload_encoded = base64.b64encode(
            json.dumps(payload.__dict__).encode()
        ).decode()
        result, _ = verify_solution(payload_encoded, self.hmac_key, check_expires=False)
        self.assertFalse(result)

    def test_verify_solution_not_expired(self):
        options = ChallengeOptions(
            algorithm="SHA-256",
            max_number=1000,
            salt_length=16,
            hmac_key=self.hmac_key,
            salt="somesalt",
            number=123,
            expires=datetime.datetime.now().astimezone() + datetime.timedelta(minutes=1)
        )
        challenge = create_challenge(options)
        payload = Payload(
            algorithm="SHA-256",
            challenge=challenge.challenge,
            number=123,
            salt=challenge.salt,
            signature=challenge.signature,
        )
        payload_encoded = base64.b64encode(
            json.dumps(payload.__dict__).encode()
        ).decode()
        result, _ = verify_solution(payload_encoded, self.hmac_key, check_expires=True)
        self.assertTrue(result)

    def test_verify_solution_expired(self):
        options = ChallengeOptions(
            algorithm="SHA-256",
            max_number=1000,
            salt_length=16,
            hmac_key=self.hmac_key,
            salt="somesalt",
            number=123,
            expires=datetime.datetime.now().astimezone() - datetime.timedelta(minutes=1)
        )
        challenge = create_challenge(options)
        payload = Payload(
            algorithm="SHA-256",
            challenge=challenge.challenge,
            number=123,
            salt=challenge.salt,
            signature=challenge.signature,
        )
        payload_encoded = base64.b64encode(
            json.dumps(payload.__dict__).encode()
        ).decode()
        result, _ = verify_solution(payload_encoded, self.hmac_key, check_expires=True)
        self.assertFalse(result)

    def test_verify_solution_malformed_expiry(self):
        options = ChallengeOptions(
            algorithm="SHA-256",
            max_number=1000,
            salt_length=16,
            hmac_key=self.hmac_key,
            salt="somesalt",
            number=123,
            expires=datetime.datetime.now().astimezone() + datetime.timedelta(minutes=1)
        )
        challenge = create_challenge(options)
        payload = Payload(
            algorithm="SHA-256",
            challenge=challenge.challenge,
            number=123,
            salt='somesalt?expires=foobar',
            signature=challenge.signature,
        )
        payload_encoded = base64.b64encode(
            json.dumps(payload.__dict__).encode()
        ).decode()
        result, _ = verify_solution(payload_encoded, self.hmac_key, check_expires=True)
        self.assertFalse(result)

    def test_valid_signature(self):
        expire_time = int(time.time()) + 600  # 10 minutes from now
        verification_data = (
            f"expire={expire_time}&fields=field1,field2&reasons=reason1,reason2"
            f"&score=3&time={int(time.time())}&verified=true"
        )
        hash_obj = hash_algorithm("SHA-256")
        hash_obj.update(verification_data.encode())
        expected_signature = hmac_hex("SHA-256", hash_obj.digest(), self.hmac_key)

        payload = {
            "algorithm": "SHA-256",
            "verificationData": verification_data,
            "signature": expected_signature,
            "verified": True,
        }
        payload_encoded = base64.b64encode(json.dumps(payload).encode()).decode()

        is_valid, data, error = verify_server_signature(payload_encoded, self.hmac_key)

        self.assertIsNone(error)
        self.assertTrue(is_valid)
        self.assertGreater(int(data.expire), 0)
        self.assertGreater(len(data.fields), 0)
        self.assertGreater(len(data.reasons), 0)
        self.assertGreater(int(data.score), 0)
        self.assertGreater(int(data.time), 0)
        self.assertTrue(data.verified)

    def test_invalid_signature(self):
        expire_time = int(time.time()) + 600
        verification_data = (
            f"expire={expire_time}&fields=field1,field2&reasons=reason1,reason2"
            f"&score=3&time={int(time.time())}&verified=true"
        )
        payload = {
            "algorithm": "SHA-256",
            "verificationData": verification_data,
            "signature": "invalidSignature",
            "verified": True,
        }
        payload_encoded = base64.b64encode(json.dumps(payload).encode()).decode()

        is_valid, _, error = verify_server_signature(payload_encoded, self.hmac_key)

        self.assertIsNone(error)
        self.assertFalse(is_valid)

    def test_expired_payload(self):
        expire_time = int(time.time()) - 600  # 10 minutes ago
        verification_data = (
            f"expire={expire_time}&fields=field1,field2&reasons=reason1,reason2"
            f"&score=3&time={int(time.time())}&verified=true"
        )
        hash_obj = hash_algorithm("SHA-256")
        hash_obj.update(verification_data.encode())
        expected_signature = hmac_hex("SHA-256", hash_obj.digest(), self.hmac_key)

        payload = {
            "algorithm": "SHA-256",
            "verificationData": verification_data,
            "signature": expected_signature,
            "verified": True,
        }
        payload_encoded = base64.b64encode(json.dumps(payload).encode()).decode()

        is_valid, _, error = verify_server_signature(payload_encoded, self.hmac_key)

        self.assertIsNotNone(error)
        self.assertFalse(is_valid)

    def test_solve_challenge(self):
        start = 0
        options = ChallengeOptions(
            algorithm="SHA-256",
            max_number=1000,
            salt_length=16,
            hmac_key=self.hmac_key,
            salt="somesalt",
            number=123,
        )
        challenge = create_challenge(options)

        solution, err = solve_challenge(
            challenge.challenge,
            challenge.salt,
            challenge.algorithm,
            1000,
            start,
        )

        self.assertIsNone(err, "Error occurred while solving the challenge")
        self.assertIsNotNone(solution, "Solution should not be None")
        self.assertEqual(
            challenge.challenge,
            hash_hex(
                challenge.algorithm, (challenge.salt + str(solution.number)).encode()
            ),
        )

    def test_solve_challenge(self):
        # Create a challenge
        options = ChallengeOptions(
            algorithm="SHA-256", number=100, hmac_key=self.hmac_key
        )

        challenge = create_challenge(options)

        solution = solve_challenge(
            challenge.challenge,
            challenge.salt,
            challenge.algorithm,
            challenge.maxnumber,
            0,
        )

        # Verify the solution
        self.assertIsNotNone(solution, "Solution should not be None")
        self.assertEqual(solution.number, 100, "Solution be 100")

    def test_hash_hex(self):
        result = hash_hex("SHA-256", "testdata".encode())
        self.assertEqual(result, hashlib.sha256("testdata".encode()).hexdigest())

    def test_hmac_hex(self):
        result = hmac_hex("SHA-256", "testdata".encode(), self.hmac_key)
        expected = hmac.new(
            self.hmac_key.encode(), "testdata".encode(), hashlib.sha256
        ).hexdigest()
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
