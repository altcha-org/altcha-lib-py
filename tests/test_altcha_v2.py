import datetime
import itertools
import json
import struct
import unittest
import unittest.mock
from typing import cast

from altcha.v2 import (
    DEFAULT_HMAC_ALGORITHM,
    Challenge,
    ChallengeParameters,
    Payload,
    ServerSignaturePayload,
    Solution,
    _canonical_json,
    _hmac_v2,
    _make_password,
    _sign_challenge_v2,
    create_challenge,
    derive_key_pbkdf2,
    derive_key_scrypt,
    derive_key_sha,
    parse_verification_data,
    solve_challenge,
    verify_server,
    verify_server_signature,
    verify_solution,
)

HMAC_KEY = "test-secret"


class TestMakePassword(unittest.TestCase):
    def test_uint32_mode(self):
        nonce = bytes.fromhex("aabbccdd")
        pwd = _make_password(nonce, 42)
        self.assertEqual(pwd, b"\xaa\xbb\xcc\xdd" + struct.pack(">I", 42))

    def test_string_mode(self):
        nonce = bytes.fromhex("aabbccdd")
        pwd = _make_password(nonce, 1234, "string")
        self.assertEqual(pwd, b"\xaa\xbb\xcc\xdd1234")


class TestCanonicalJSON(unittest.TestCase):
    def test_sorts_keys(self):
        result = _canonical_json({"z": 1, "a": 2, "m": 3})
        self.assertEqual(result, '{"a":2,"m":3,"z":1}')

    def test_keeps_null(self):
        result = _canonical_json({"a": 1, "b": None, "c": 3})
        self.assertEqual(result, '{"a":1,"b":null,"c":3}')

    def test_nested(self):
        result = _canonical_json({"z": {"b": 2, "a": 1}})
        self.assertEqual(result, '{"z":{"a":1,"b":2}}')

    def test_matches_js(self):
        # Expected strings produced by altcha-lib's canonicalJSON on the same JSON.
        vectors = [
            (
                "[1e-7,1.0,-0.0,1e16,1e21,123456789012345678,1.5e-6,1e-6,1e400]",
                "[1e-7,1,0,10000000000000000,1e+21,123456789012345680,"
                "0.0000015,0.000001,null]",
            ),
            (
                '{"big":12345678901234567890,"ok":9007199254740993}',
                '{"big":12345678901234567000,"ok":9007199254740992}',
            ),
            (
                '{"10":1,"9":2,"a":3,"01":4,"4294967294":5,"4294967295":6,"-1":7}',
                '{"9":2,"10":1,"4294967294":5,"-1":7,"01":4,"4294967295":6,"a":3}',
            ),
            ('{"\\uff61":1,"\\ud83d\\ude00":2}', '{"\U0001f600":2,"\uff61":1}'),
            (
                '{"s":"\\u0000\\u007f\\u2028\\b\\ud800 \\udc00x \\ud83d\\ude00"}',
                '{"s":"\\u0000\x7f\u2028\\b\\ud800 \\udc00x \U0001f600"}',
            ),
            (
                '{"arr":[{"b":1,"a":2,"1":0},[{"y":1,"x":2}]]}',
                '{"arr":[{"1":0,"b":1,"a":2},[{"y":1,"x":2}]]}',
            ),
        ]
        for source, expected in vectors:
            with self.subTest(source=source):
                self.assertEqual(_canonical_json(json.loads(source)), expected)


class TestDeriveKeySha(unittest.TestCase):
    def test_single_iteration(self):
        params = ChallengeParameters(
            algorithm="SHA-256",
            nonce="aa",
            salt="bb",
            cost=1,
            key_length=32,
            key_prefix="00",
        )
        import hashlib

        expected = hashlib.sha256(b"\xbb\xaa").digest()[:32]
        result = derive_key_sha(params, b"\xbb", b"\xaa")
        self.assertEqual(result, expected)

    def test_multi_iteration(self):
        params = ChallengeParameters(
            algorithm="SHA-256",
            nonce="aa",
            salt="bb",
            cost=3,
            key_length=32,
            key_prefix="00",
        )
        import hashlib

        h = hashlib.sha256(b"\xbb\xaa").digest()
        h = hashlib.sha256(h).digest()
        h = hashlib.sha256(h).digest()
        result = derive_key_sha(params, b"\xbb", b"\xaa")
        self.assertEqual(result, h[:32])

    def test_key_length_truncation(self):
        params = ChallengeParameters(
            algorithm="SHA-256",
            nonce="aa",
            salt="bb",
            cost=1,
            key_length=8,
            key_prefix="00",
        )
        result = derive_key_sha(params, b"\xbb", b"\xaa")
        self.assertEqual(len(result), 8)

    def test_unrecognized_algorithm_uses_sha256(self):
        # altcha-lib sha.ts deriveKey output for SHA-256, salt 00112233, password aabbccdd.
        expected = "818a3c3da22f44d6d4b92bd6168e71a9228e2b3061b77a018a1bb786206986f2"
        for algorithm in ("SHA-256", "SHA-1", "sha-512", "MD5"):
            with self.subTest(algorithm=algorithm):
                params = ChallengeParameters(
                    algorithm=algorithm, nonce="", salt="", cost=2, key_length=32
                )
                result = derive_key_sha(
                    params, bytes.fromhex("00112233"), bytes.fromhex("aabbccdd")
                )
                self.assertEqual(result.hex(), expected)


class TestDeriveKeyPBKDF2(unittest.TestCase):
    def test_basic(self):
        import hashlib

        params = ChallengeParameters(
            algorithm="PBKDF2/SHA-256",
            nonce="aa",
            salt="bb",
            cost=1000,
            key_length=32,
            key_prefix="00",
        )
        expected = hashlib.pbkdf2_hmac("sha256", b"\xaa", b"\xbb", 1000, 32)
        result = derive_key_pbkdf2(params, b"\xbb", b"\xaa")
        self.assertEqual(result, expected)

    def test_unrecognized_algorithm_uses_sha256(self):
        # altcha-lib pbkdf2.ts deriveKey output for PBKDF2/SHA-256, salt 00112233,
        # password aabbccdd.
        expected = "3198c239f81895ecedabba4db70278e53a7e622d7c45467719b8fbeb9b41e79c"
        for algorithm in ("PBKDF2/SHA-256", "PBKDF2/SHA-1", "PBKDF2/sha-512", "PBKDF2"):
            with self.subTest(algorithm=algorithm):
                params = ChallengeParameters(
                    algorithm=algorithm, nonce="", salt="", cost=2, key_length=32
                )
                result = derive_key_pbkdf2(
                    params, bytes.fromhex("00112233"), bytes.fromhex("aabbccdd")
                )
                self.assertEqual(result.hex(), expected)


class TestDeriveKeyScrypt(unittest.TestCase):
    def test_basic(self):
        import hashlib

        params = ChallengeParameters(
            algorithm="SCRYPT",
            nonce="aa",
            salt="bb",
            cost=1024,
            key_length=32,
            key_prefix="00",
            memory_cost=8,
            parallelism=1,
        )
        n, r, p = 1024, 8, 1
        expected = hashlib.scrypt(
            b"\xaa", salt=b"\xbb", n=n, r=r, p=p, dklen=32, maxmem=2 * 128 * n * r
        )
        result = derive_key_scrypt(params, b"\xbb", b"\xaa")
        self.assertEqual(result, expected)


class TestCreateChallenge(unittest.TestCase):
    def test_unsigned_challenge(self):
        ch = create_challenge("SHA-256", cost=1)
        self.assertIsNone(ch.signature)
        self.assertIsNotNone(ch.parameters.nonce)
        self.assertIsNotNone(ch.parameters.salt)
        self.assertEqual(len(ch.parameters.nonce), 32)
        self.assertEqual(len(ch.parameters.salt), 32)

    def test_signed_challenge(self):
        ch = create_challenge("SHA-256", cost=1, hmac_secret=HMAC_KEY)
        assert ch.signature is not None
        self.assertGreater(len(ch.signature), 0)

    def test_bytes_hmac_secret(self):
        # Non-UTF-8 binary key must be accepted (issue #20)
        key = bytes(range(256))
        ch = create_challenge("SHA-256", cost=1, counter=5, hmac_secret=key)
        assert ch.signature is not None
        sol = solve_challenge(ch)
        assert sol is not None
        payload = Payload(ch, sol).to_base64()
        result = verify_solution(payload, key)
        self.assertTrue(result.verified)
        self.assertFalse(result.invalid_signature)

    def test_deterministic_counter(self):
        ch = create_challenge("SHA-256", cost=1, counter=42, hmac_secret=HMAC_KEY)
        # key_prefix should be the first 16 bytes (key_length//2) of the derived key
        self.assertIsNotNone(ch.parameters.key_prefix)
        self.assertEqual(len(ch.parameters.key_prefix), 32)  # 16 bytes = 32 hex chars

    def test_expires_at_datetime(self):
        exp = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        ch = create_challenge("SHA-256", cost=1, expires_at=exp, hmac_secret=HMAC_KEY)
        self.assertIsNotNone(ch.parameters.expires_at)
        self.assertEqual(ch.parameters.expires_at, int(exp.timestamp()))

    def test_key_signature(self):
        ch = create_challenge(
            "SHA-256",
            cost=1,
            counter=0,
            hmac_secret=HMAC_KEY,
            hmac_key_secret="key-secret",
        )
        self.assertIsNotNone(ch.parameters.key_signature)

    def test_empty_secrets_are_unset(self):
        for empty in ("", b""):
            with self.subTest(empty=empty):
                ch = create_challenge(
                    "SHA-256", cost=1, counter=0, hmac_secret=empty, hmac_key_secret="k"
                )
                self.assertIsNone(ch.signature)
                self.assertIsNone(ch.parameters.key_signature)
                ch = create_challenge(
                    "SHA-256",
                    cost=1,
                    counter=0,
                    hmac_secret=HMAC_KEY,
                    hmac_key_secret=empty,
                )
                self.assertIsNotNone(ch.signature)
                self.assertIsNone(ch.parameters.key_signature)


class TestSolveChallenge(unittest.TestCase):
    def test_solves_sha(self):
        ch = create_challenge("SHA-256", cost=1, counter=7, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None
        self.assertEqual(sol.counter, 7)

    def test_solves_string_counter_mode(self):
        ch = create_challenge("SHA-256", cost=1, counter=1234, counter_mode="string")
        sol = solve_challenge(ch, counter_mode="string", timeout=5)
        assert sol is not None
        self.assertEqual(sol.counter, 1234)

    def test_solves_pbkdf2(self):
        ch = create_challenge("PBKDF2/SHA-256", cost=1, counter=3, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None
        self.assertEqual(sol.counter, 3)

    def test_solves_scrypt(self):
        ch = create_challenge(
            "SCRYPT", cost=1024, memory_cost=8, counter=2, hmac_secret=HMAC_KEY
        )
        sol = solve_challenge(ch)
        assert sol is not None
        self.assertEqual(sol.counter, 2)

    def test_returns_derived_key_hex(self):
        ch = create_challenge("SHA-256", cost=1, counter=5, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None
        # derived_key should be a valid hex string
        bytes.fromhex(sol.derived_key)  # should not raise

    def test_timeout_returns_none(self):
        # Create a challenge with an impossible prefix
        ch = create_challenge("SHA-256", cost=1)
        ch.parameters.key_prefix = "ff" * 16  # extremely unlikely
        sol = solve_challenge(ch, timeout=0.001)
        self.assertIsNone(sol)

    def test_timeout_with_counter_partition(self):
        ch = create_challenge("SHA-256", cost=1)
        ch.parameters.key_prefix = "ff"
        counters: list[int] = []

        def derive_key(params, salt, password):
            counters.append(struct.unpack(">I", password[-4:])[0])
            if len(counters) > 100:
                raise AssertionError("timeout never fired")
            return b"\x00" * 32

        # Each monotonic() call advances one second: the deadline passes after 5 tries.
        with unittest.mock.patch(
            "altcha.v2.time.monotonic", side_effect=itertools.count()
        ):
            sol = solve_challenge(
                ch, derive_key, counter_start=1, counter_step=2, timeout=5
            )
        self.assertIsNone(sol)
        self.assertEqual(counters, [1, 3, 5, 7, 9])


class TestVerifySolution(unittest.TestCase):
    def _make_payload(self, counter=5, **create_kwargs) -> str:
        ch = create_challenge(
            "SHA-256", cost=1, counter=counter, hmac_secret=HMAC_KEY, **create_kwargs
        )
        sol = solve_challenge(ch)
        assert sol is not None
        return Payload(ch, sol).to_base64()

    def test_valid(self):
        payload = self._make_payload()
        result = verify_solution(payload, HMAC_KEY)
        self.assertTrue(result.verified)
        self.assertFalse(result.expired)
        self.assertFalse(result.invalid_signature)
        self.assertFalse(result.invalid_solution)

    def test_wrong_hmac_key(self):
        payload = self._make_payload()
        result = verify_solution(payload, "wrong-key")
        self.assertFalse(result.verified)
        self.assertTrue(result.invalid_signature)

    def test_expired(self):
        past = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
        payload = self._make_payload(expires_at=past)
        result = verify_solution(payload, HMAC_KEY)
        self.assertFalse(result.verified)
        self.assertTrue(result.expired)

    def test_not_expired(self):
        future = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        payload = self._make_payload(expires_at=future)
        result = verify_solution(payload, HMAC_KEY)
        self.assertTrue(result.verified)

    def test_unsigned_challenge_fails(self):
        ch = create_challenge("SHA-256", cost=1, counter=0)  # no hmac_secret
        sol = solve_challenge(ch)
        assert sol is not None
        payload = Payload(ch, sol).to_base64()
        result = verify_solution(payload, HMAC_KEY)
        self.assertFalse(result.verified)
        self.assertTrue(result.invalid_signature)

    def test_empty_secret_raises(self):
        # A challenge forged with the empty key must not verify under an empty secret.
        params = create_challenge("SHA-256", cost=1, counter=0).parameters
        ch = _sign_challenge_v2(DEFAULT_HMAC_ALGORITHM, params, None, "", None)
        sol = solve_challenge(ch)
        assert sol is not None
        for empty in ("", b""):
            with self.subTest(empty=empty), self.assertRaises(ValueError):
                verify_solution(Payload(ch, sol), empty)

    def test_tampered_counter_fails(self):
        ch = create_challenge("SHA-256", cost=1, counter=5, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None
        # Use a different counter in the solution
        bad_sol = Solution(counter=sol.counter + 1, derived_key=sol.derived_key)
        payload = Payload(ch, bad_sol).to_base64()
        result = verify_solution(payload, HMAC_KEY)
        self.assertFalse(result.verified)
        self.assertTrue(result.invalid_solution)

    def test_invalid_payload(self):
        result = verify_solution("not-valid-base64!!!", HMAC_KEY)
        self.assertFalse(result.verified)
        self.assertIsNotNone(result.error)

    def test_fast_path_key_signature(self):
        KEY_SIG_SECRET = "key-sig-secret"
        ch = create_challenge(
            "SHA-256",
            cost=1,
            counter=3,
            hmac_secret=HMAC_KEY,
            hmac_key_secret=KEY_SIG_SECRET,
        )
        sol = solve_challenge(ch)
        assert sol is not None
        payload = Payload(ch, sol).to_base64()
        result = verify_solution(payload, HMAC_KEY, hmac_key_secret=KEY_SIG_SECRET)
        self.assertTrue(result.verified)

    def test_fast_path_wrong_key_signature_secret(self):
        KEY_SIG_SECRET = "key-sig-secret"
        ch = create_challenge(
            "SHA-256",
            cost=1,
            counter=3,
            hmac_secret=HMAC_KEY,
            hmac_key_secret=KEY_SIG_SECRET,
        )
        sol = solve_challenge(ch)
        assert sol is not None
        payload = Payload(ch, sol).to_base64()
        result = verify_solution(payload, HMAC_KEY, hmac_key_secret="wrong-secret")
        self.assertFalse(result.verified)
        self.assertTrue(result.invalid_solution)

    def test_fast_path_malformed_derived_key(self):
        KEY_SIG_SECRET = "key-sig-secret"
        ch = create_challenge(
            "SHA-256",
            cost=1,
            counter=3,
            hmac_secret=HMAC_KEY,
            hmac_key_secret=KEY_SIG_SECRET,
        )
        sol = solve_challenge(ch)
        assert sol is not None
        key = sol.derived_key
        for derived_key in ("zz" * 32, key[:-1], 5, None, f"{key[:2]} {key[2:]}"):
            with self.subTest(derived_key=derived_key):
                bad_sol = Solution(counter=sol.counter, derived_key=derived_key)
                result = verify_solution(
                    Payload(ch, bad_sol), HMAC_KEY, hmac_key_secret=KEY_SIG_SECRET
                )
                self.assertFalse(result.verified)
                self.assertTrue(result.invalid_solution)
        upper_sol = Solution(counter=sol.counter, derived_key=key.upper())
        result = verify_solution(
            Payload(ch, upper_sol), HMAC_KEY, hmac_key_secret=KEY_SIG_SECRET
        )
        self.assertTrue(result.verified)

    def test_slow_path_enforces_key_prefix(self):
        # Regression test: the fallback (no key signature) verification path must
        # reject a solution whose derived key is genuinely correct for its counter
        # but does not satisfy the challenge's key_prefix. Previously only
        # derived_key == KDF(counter) was checked, letting a client submit any
        # counter after a single KDF execution and skip the prefix search entirely.
        ch = create_challenge("SHA-256", cost=10, hmac_secret=HMAC_KEY)

        # Learn the honest KDF output for counter 0 with exactly one hash
        # computation: solve a probe copy of the challenge whose key_prefix is ""
        # (matches immediately, no search).
        probe_params = ChallengeParameters(
            **{**ch.parameters.__dict__, "key_prefix": ""}
        )
        probe_ch = Challenge(parameters=probe_params, signature=None)
        honest = solve_challenge(probe_ch)
        assert honest is not None
        self.assertEqual(honest.counter, 0)

        # Pick a key_prefix the honest key is guaranteed not to satisfy: a byte
        # can't be both 0x00 and 0xff.
        mismatched_prefix = "ff" if honest.derived_key.startswith("00") else "00"
        ch.parameters.key_prefix = mismatched_prefix
        signed = _sign_challenge_v2(
            DEFAULT_HMAC_ALGORITHM, ch.parameters, None, HMAC_KEY
        )

        # Submit the honestly-derived key/counter pair (one KDF execution, no
        # prefix search) against the challenge whose signed key_prefix it does
        # not satisfy.
        bad_sol = Solution(counter=honest.counter, derived_key=honest.derived_key)
        payload = Payload(signed, bad_sol).to_base64()
        result = verify_solution(payload, HMAC_KEY)
        self.assertFalse(result.verified)
        self.assertTrue(result.invalid_solution)

    def test_slow_path_uppercase_key_prefix(self):
        for prefix in ("F2", "F"):
            with self.subTest(prefix=prefix):
                params = create_challenge("SHA-256", cost=1).parameters
                # Uppercase prefix signed as-is, as another issuer may produce.
                params.key_prefix = prefix
                ch = _sign_challenge_v2(
                    DEFAULT_HMAC_ALGORITHM, params, None, HMAC_KEY, None
                )
                sol = solve_challenge(ch, timeout=5)
                assert sol is not None
                self.assertTrue(sol.derived_key.startswith(prefix.lower()))
                result = verify_solution(Payload(ch, sol), HMAC_KEY)
                self.assertTrue(result.verified)

    def test_create_lowercases_key_prefix(self):
        ch = create_challenge("SHA-256", cost=1, key_prefix="F2A")
        self.assertEqual(ch.parameters.key_prefix, "f2a")

    def test_slow_path_invalid_counter(self):
        ch = create_challenge("SHA-256", cost=1, counter=3, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None
        c = sol.counter
        for counter in (-1, 2**32 + c, str(c), float(c), None, True):
            with self.subTest(counter=counter):
                bad_sol = Solution(counter=counter, derived_key=sol.derived_key)
                result = verify_solution(Payload(ch, bad_sol).to_base64(), HMAC_KEY)
                self.assertFalse(result.verified)
                self.assertTrue(result.invalid_solution)

    def test_malformed_fields(self):
        ch = create_challenge("SHA-256", cost=1, counter=3, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None

        tampered = Challenge.from_dict(ch.to_dict())
        tampered.parameters.expires_at = "9999999999"
        result = verify_solution(Payload(tampered, sol), HMAC_KEY)
        self.assertFalse(result.expired)
        self.assertTrue(result.invalid_signature)

        for signature in (123, "é", "\ud800"):
            with self.subTest(signature=signature):
                bad_ch = Challenge(parameters=ch.parameters, signature=signature)
                result = verify_solution(Payload(bad_ch, sol), HMAC_KEY)
                self.assertFalse(result.verified)
                self.assertTrue(result.invalid_signature)

        for derived_key in ("é", 5, "\ud800"):
            with self.subTest(derived_key=derived_key):
                bad_sol = Solution(counter=sol.counter, derived_key=derived_key)
                result = verify_solution(Payload(ch, bad_sol), HMAC_KEY)
                self.assertFalse(result.verified)
                self.assertTrue(result.invalid_solution)

    def test_js_string_counter_mode(self):
        # altcha-lib createChallenge({counter: 1234, counterMode: 'string'}), secret "h".
        ch = Challenge.from_dict(
            {
                "parameters": {
                    "algorithm": "SHA-256",
                    "cost": 1,
                    "keyLength": 32,
                    "keyPrefix": "f053b63e7d151cc92d2e3c79af5d37cf",
                    "nonce": "9fd71ed5d4d76048d3cfb98b2a658d7b",
                    "salt": "b1662109960ba9534ac4a5a62340f1a7",
                },
                "signature": "614fc0a8ae77a2d8773973d53f72cdd42e169b4e6b594e635223e2196782091b",
            }
        )
        sol = solve_challenge(ch, counter_mode="string", timeout=5)
        assert sol is not None
        self.assertEqual(sol.counter, 1234)
        result = verify_solution(Payload(ch, sol), "h", counter_mode="string")
        self.assertTrue(result.verified)
        result = verify_solution(Payload(ch, sol), "h")
        self.assertTrue(result.invalid_solution)

    def test_js_signed_data(self):
        # Payload from altcha-lib createChallenge/solveChallenge (secret "test-secret")
        # with data {z: null, f: 1e-7, n: 1.5, i: 1.0, big: 2 ** 64, "10": "x",
        # "9": "y", b: true, s: "é\u2028\ud800😀"}.
        payload = (
            "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY29zdCI6"
            "MSwiZGF0YSI6eyI5IjoieSIsIjEwIjoieCIsImIiOnRydWUsImJpZyI6MTg0NDY3NDQwNzM3MDk1"
            "NTIwMDAsImYiOjFlLTcsImkiOjEsIm4iOjEuNSwicyI6IsOp4oCoXHVkODAw8J+YgCIsInoiOm51"
            "bGx9LCJrZXlMZW5ndGgiOjMyLCJrZXlQcmVmaXgiOiIyM2RlY2I0YzY1NzFiMDE0NjhhNGExNTU0"
            "MTJkNjliOCIsIm5vbmNlIjoiMGE4N2IyZGFmZGQ5NjA2YWUzMGQyMmJlOTUwMGU5MTMiLCJzYWx0"
            "IjoiNDc3MWE1ODhmNDU4MGQ1ZjllYWVmY2FkYjU4MTE4ODUifSwic2lnbmF0dXJlIjoiNWYzZjNj"
            "MDIzYzg2OTYxZDhiZWRlZjY0OWUxN2RiN2JhY2FmOTQ3ZDY5MjFiMTZkNWM1MGRkMGMxZDk4MjUw"
            "MiJ9LCJzb2x1dGlvbiI6eyJjb3VudGVyIjo1LCJkZXJpdmVkS2V5IjoiMjNkZWNiNGM2NTcxYjAx"
            "NDY4YTRhMTU1NDEyZDY5YjgwOWEyZGFkZGY2NDM0ODYwN2Y1NWJhYTFkOGMwNWIyNyIsInRpbWUi"
            "OjB9fQ=="
        )
        result = verify_solution(payload, HMAC_KEY)
        self.assertFalse(result.invalid_signature)
        self.assertTrue(result.verified)

    def test_payload_object(self):
        ch = create_challenge("SHA-256", cost=1, counter=2, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None
        payload_obj = Payload(ch, sol)
        result = verify_solution(payload_obj, HMAC_KEY)
        self.assertTrue(result.verified)

    def test_pbkdf2_roundtrip(self):
        ch = create_challenge("PBKDF2/SHA-256", cost=1, counter=1, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None
        payload = Payload(ch, sol).to_base64()
        result = verify_solution(payload, HMAC_KEY)
        self.assertTrue(result.verified)

    def test_scrypt_roundtrip(self):
        ch = create_challenge(
            "SCRYPT", cost=1024, memory_cost=8, counter=0, hmac_secret=HMAC_KEY
        )
        sol = solve_challenge(ch)
        assert sol is not None
        payload = Payload(ch, sol).to_base64()
        result = verify_solution(payload, HMAC_KEY)
        self.assertTrue(result.verified)


class TestPayloadSerialization(unittest.TestCase):
    def test_roundtrip(self):
        ch = create_challenge("SHA-256", cost=1, counter=10, hmac_secret=HMAC_KEY)
        sol = solve_challenge(ch)
        assert sol is not None
        payload = Payload(ch, sol)
        encoded = payload.to_base64()
        decoded = Payload.from_base64(encoded)
        self.assertEqual(decoded.solution.counter, sol.counter)
        self.assertEqual(decoded.solution.derived_key, sol.derived_key)
        self.assertEqual(decoded.challenge.parameters.nonce, ch.parameters.nonce)
        self.assertEqual(decoded.challenge.signature, ch.signature)


class TestParseVerificationData(unittest.TestCase):
    def test_bool_true(self):
        result = parse_verification_data("verified=true")
        assert result is not None
        self.assertIs(result["verified"], True)

    def test_bool_false(self):
        result = parse_verification_data("verified=false")
        assert result is not None
        self.assertIs(result["verified"], False)

    def test_int(self):
        result = parse_verification_data("expire=1234567890")
        assert result is not None
        self.assertEqual(result["expire"], 1234567890)
        self.assertIsInstance(result["expire"], int)

    def test_float(self):
        result = parse_verification_data("score=0.9")
        assert result is not None
        self.assertAlmostEqual(result["score"], 0.9)
        self.assertIsInstance(result["score"], float)

    def test_array_fields(self):
        result = parse_verification_data("fields=email,name&reasons=ok,spam")
        assert result is not None
        self.assertEqual(result["fields"], ["email", "name"])
        self.assertEqual(result["reasons"], ["ok", "spam"])

    def test_string_value(self):
        result = parse_verification_data("classification=GOOD")
        assert result is not None
        self.assertEqual(result["classification"], "GOOD")

    def test_empty_string_returns_empty_dict(self):
        self.assertEqual(parse_verification_data(""), {})

    def test_unparseable_input_returns_none(self):
        # bytes parse into bytes pairs, which the str-based coercion rejects
        self.assertIsNone(parse_verification_data(cast(str, b"verified=true")))


class TestVerifyServerSignature(unittest.TestCase):
    def _make_payload(
        self, expire_offset: int = 600, verified: bool = True
    ) -> ServerSignaturePayload:
        import time as _time

        expire = int(_time.time()) + expire_offset
        vdata = f"expire={expire}&fields=email,name&score=0.9&verified={str(verified).lower()}"
        hash_name = "sha256"
        data_hash = __import__("hashlib").new(hash_name, vdata.encode()).digest()
        sig = _hmac_v2("SHA-256", data_hash, HMAC_KEY).hex()
        return ServerSignaturePayload(
            algorithm="SHA-256",
            signature=sig,
            verification_data=vdata,
            verified=verified,
        )

    def test_valid(self):
        payload = self._make_payload()
        result = verify_server_signature(payload, HMAC_KEY)
        self.assertTrue(result.verified)
        self.assertFalse(result.expired)
        self.assertFalse(result.invalid_signature)
        self.assertFalse(result.invalid_solution)
        assert result.verification_data is not None
        self.assertIsInstance(result.verification_data["expire"], int)
        self.assertEqual(result.verification_data["fields"], ["email", "name"])
        self.assertAlmostEqual(result.verification_data["score"], 0.9)

    def test_wrong_secret(self):
        payload = self._make_payload()
        result = verify_server_signature(payload, "wrong-secret")
        self.assertFalse(result.verified)
        self.assertTrue(result.invalid_signature)

    def test_empty_secret_raises(self):
        payload = self._make_payload()
        payload.signature = _hmac_v2(
            "SHA-256",
            __import__("hashlib").sha256(payload.verification_data.encode()).digest(),
            "",
        ).hex()
        for empty in ("", b""):
            with self.subTest(empty=empty), self.assertRaises(ValueError):
                verify_server_signature(payload, empty)

    def test_expired(self):
        payload = self._make_payload(expire_offset=-600)
        result = verify_server_signature(payload, HMAC_KEY)
        self.assertFalse(result.verified)
        self.assertTrue(result.expired)

    def test_not_verified(self):
        payload = self._make_payload(verified=False)
        result = verify_server_signature(payload, HMAC_KEY)
        self.assertFalse(result.verified)
        self.assertTrue(result.invalid_solution)

    def test_base64_payload(self):
        import base64
        import json

        p = self._make_payload()
        encoded = base64.b64encode(
            json.dumps(
                {
                    "algorithm": p.algorithm,
                    "signature": p.signature,
                    "verificationData": p.verification_data,
                    "verified": p.verified,
                }
            ).encode()
        ).decode()
        result = verify_server_signature(encoded, HMAC_KEY)
        self.assertTrue(result.verified)

    def test_invalid_base64(self):
        result = verify_server_signature("not-valid!!!", HMAC_KEY)
        self.assertFalse(result.verified)
        self.assertTrue(result.invalid_signature)


class TestVerifyServer(unittest.TestCase):
    URL = "https://sentinel.example.com/v1/verify/signature"

    def setUp(self):
        self._sleep_calls: list[float] = []
        self._sleep_patcher = unittest.mock.patch(
            "altcha.v2.time.sleep", side_effect=self._sleep_calls.append
        )
        self._sleep_patcher.start()
        self.addCleanup(self._sleep_patcher.stop)

    def test_success(self):
        result_data = {
            "apiKey": "key_1",
            "verificationData": {"verified": True},
            "verified": True,
        }
        calls = []

        def post(url, data, headers, timeout):
            calls.append((url, data, headers, timeout))
            return 200, json.dumps(result_data).encode()

        result = verify_server("payload", self.URL, http_post=post)
        self.assertTrue(result.verified)
        self.assertEqual(result.api_key, "key_1")
        self.assertEqual(result.verification_data, {"verified": True})
        self.assertIsNone(result.reason)
        self.assertEqual(len(calls), 1)

    def test_secret_included_in_body(self):
        calls = []

        def post(url, data, headers, timeout):
            calls.append(data)
            return 200, json.dumps({"verified": True}).encode()

        verify_server("payload", self.URL, secret="sec_123", http_post=post)
        self.assertEqual(
            json.loads(calls[0]), {"payload": "payload", "secret": "sec_123"}
        )

    def test_secret_omitted_when_not_given(self):
        calls = []

        def post(url, data, headers, timeout):
            calls.append(data)
            return 200, json.dumps({"verified": True}).encode()

        verify_server("payload", self.URL, http_post=post)
        self.assertEqual(json.loads(calls[0]), {"payload": "payload"})

    def test_400_is_terminal_not_retried(self):
        calls = []

        def post(url, data, headers, timeout):
            calls.append(1)
            return 400, json.dumps({"error": "INVALID_PAYLOAD"}).encode()

        result = verify_server("payload", self.URL, retries=3, http_post=post)
        self.assertFalse(result.verified)
        self.assertEqual(result.reason, "INVALID_PAYLOAD")
        self.assertEqual(len(calls), 1)

    def test_network_error_retried_then_fails(self):
        calls = []

        def post(url, data, headers, timeout):
            calls.append(1)
            raise OSError("fetch failed")

        result = verify_server("payload", self.URL, retries=2, http_post=post)
        self.assertFalse(result.verified)
        self.assertEqual(result.reason, "fetch failed")
        self.assertEqual(len(calls), 3)

    def test_network_error_then_success(self):
        calls = []

        def post(url, data, headers, timeout):
            calls.append(1)
            if len(calls) < 2:
                raise OSError("fetch failed")
            return 200, json.dumps({"verified": True}).encode()

        result = verify_server("payload", self.URL, retries=2, http_post=post)
        self.assertTrue(result.verified)
        self.assertEqual(len(calls), 2)

    def test_server_signature_payload_serialized(self):
        payload = ServerSignaturePayload(
            algorithm="SHA-256",
            signature="sig",
            verification_data="verified=true",
            verified=True,
        )
        calls = []

        def post(url, data, headers, timeout):
            calls.append(data)
            return 200, json.dumps({"verified": True}).encode()

        verify_server(payload, self.URL, http_post=post)
        sent = json.loads(calls[0])
        self.assertEqual(
            sent["payload"],
            {
                "algorithm": "SHA-256",
                "signature": "sig",
                "verificationData": "verified=true",
                "verified": True,
            },
        )

    def test_fixed_backoff(self):
        def post(url, data, headers, timeout):
            raise OSError("fail")

        verify_server(
            "payload",
            self.URL,
            retries=2,
            retry_delay=0.5,
            retry_backoff="fixed",
            http_post=post,
        )
        self.assertEqual(self._sleep_calls, [0.5, 0.5])

    def test_exponential_backoff(self):
        def post(url, data, headers, timeout):
            raise OSError("fail")

        verify_server(
            "payload",
            self.URL,
            retries=2,
            retry_delay=0.5,
            retry_backoff="exponential",
            http_post=post,
        )
        self.assertEqual(self._sleep_calls, [0.5, 1.0])


if __name__ == "__main__":
    unittest.main()
