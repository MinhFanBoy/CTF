from __future__ import annotations

import secrets
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes
from Crypto.Util.Padding import pad

from backend.config import *
from backend.services.account_hash import account_route_digest
from backend.services.device_hash import device_route_digest


MIX_MATRIX = [
    [73, 41, 19],
    [29, 97, 53],
    [61, 31, 89],
]

MIX_CONSTANTS = [
    0x1337133713371337,
    0xDEADBEEFCAFEBABE,
    0x4242424242424242,
]

SID_PREFIX = b"SID|"
SID_SEPARATOR = b"|"
SID_SUFFIX = b"|OK"
SID_FIELD_OFFSETS = (24, 112, 200)

def sid_filler(length: int) -> bytes:
    pattern = b"KMACTF-2026"
    return (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]


def random_sid_state() -> tuple[int, int, int]:
    return (
        secrets.randbits(SID_FIELD_BITS),
        secrets.randbits(SID_FIELD_BITS),
        secrets.randbits(SID_FIELD_BITS),
    )

def sid_base_blob() -> bytes:
    blob = bytearray(sid_filler(SID_TOTAL_BYTES))

    blob[0:len(SID_PREFIX)] = SID_PREFIX
    blob[-len(SID_SUFFIX):] = SID_SUFFIX

    for off in SID_FIELD_OFFSETS:
        if off < 0 or off + MIXED_FIELD_BYTES > SID_TOTAL_BYTES:
            raise ValueError("bad SID field offset")
        blob[off:off + MIXED_FIELD_BYTES] = b"\x00" * MIXED_FIELD_BYTES

    return bytes(blob)


def encode_sid(state: tuple[int, int, int]) -> int:
    state_values = [int(value) for value in state]

    for value in state_values:
        if not (0 <= value < 2 ** SID_FIELD_BITS):
            raise ValueError("SID state out of range")

    fields = []

    for row, const in zip(MIX_MATRIX, MIX_CONSTANTS):
        value = sum(a * b for a, b in zip(row, state_values)) + const
        if value >= 2 ** (8 * MIXED_FIELD_BYTES):
            raise ValueError("mixed SID field overflow")
        fields.append(value)

    blob = bytearray(sid_base_blob())

    for off, value in zip(SID_FIELD_OFFSETS, fields):
        blob[off:off + MIXED_FIELD_BYTES] = value.to_bytes(
            MIXED_FIELD_BYTES,
            "big",
        )

    return bytes_to_long(bytes(blob))

@dataclass
class WrappedMaterial:
    auth_key_hashed: str
    master_key_enc: bytes
    share_key_enc: bytes
    share_key_nonce: bytes
    share_key_tag: bytes
    share_key_pub: tuple[int, int]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor inputs must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def nonce_from_identity(account_id: int, device_id: int) -> bytes:
    material = account_route_digest(account_id) + device_route_digest(device_id)
    return SHA256.new(material).digest()[:GCM_NONCE_SIZE]



class RegisteredClient:
    def __init__(self, password: bytes, salt: bytes, account_id: int, device_id: int):
        self.password = password
        self.salt = salt
        self.account_id = account_id
        self.device_id = device_id
        self._generate_keys()
        self._prepare_crypto_material()

    def _generate_keys(self) -> None:
        keys = PBKDF2(self.password, self.salt, 32, count=1000, hmac_hash_module=SHA512)
        self.enc_key = keys[:16]
        self.auth_key = keys[16:]
        self.auth_key_hashed = SHA256.new(self.auth_key).hexdigest()

        self.master_key = GCM_KEY
        self.share_key = RSA.generate(RSA_BITS)
        self.share_key_pub = (int(self.share_key.n), int(self.share_key.e))

    def _prepare_crypto_material(self) -> None:
        cipher_enc = AES.new(self.enc_key, AES.MODE_ECB)
        self.master_key_enc = cipher_enc.encrypt(self.master_key)

        blob = self.format_private_key_blob()
        self.share_key_mask = get_random_bytes(KEY_BLOB_LEN)
        protected_blob = xor_bytes(blob, self.share_key_mask)

        self.share_key_nonce = nonce_from_identity(self.account_id, self.device_id)
        cipher_master = AES.new(self.master_key, AES.MODE_GCM, nonce=self.share_key_nonce)
        self.share_key_enc, self.share_key_tag = cipher_master.encrypt_and_digest(protected_blob)

    def format_private_key_blob(self) -> bytes:
        data = b"".join(
            [
                long_to_bytes(int(self.share_key.p), P_LEN),
                long_to_bytes(int(self.share_key.q), Q_LEN),
                long_to_bytes(int(self.share_key.d), D_LEN),
            ]
        )
        if len(data) != KEY_BLOB_LEN or len(data) % BLOCK_SIZE != 0:
            raise ValueError("bad private key blob layout")
        return data

    def public_material(self) -> WrappedMaterial:
        return WrappedMaterial(
            auth_key_hashed=self.auth_key_hashed,
            master_key_enc=self.master_key_enc,
            share_key_enc=self.share_key_enc,
            share_key_nonce=self.share_key_nonce,
            share_key_tag=self.share_key_tag,
            share_key_pub=self.share_key_pub,
        )


class LoginVerifier:
    def __init__(self, password: bytes, salt: bytes):
        keys = PBKDF2(password, salt, 32, count=1000, hmac_hash_module=SHA512)
        self.enc_key = keys[:16]
        self.auth_key = keys[16:]
        self.auth_key_hashed = SHA256.new(self.auth_key).hexdigest()
        self.cipher_enc = AES.new(self.enc_key, AES.MODE_ECB)

    def login_step2(
        self,
        sid_enc: bytes,
        share_key_enc: bytes,
        share_key_tag: bytes,
        share_key_nonce: bytes,
        share_key_mask: bytes,
        master_key_enc: bytes,
    ) -> bytes:
        master_key = self.cipher_enc.decrypt(master_key_enc)
        cipher_master = AES.new(master_key, AES.MODE_GCM, nonce=share_key_nonce)
        protected_blob = cipher_master.decrypt_and_verify(share_key_enc, share_key_tag)
        share_key_blob = xor_bytes(protected_blob, share_key_mask)
        p, q, d = self.parse_private_key_blob(share_key_blob)
        return self.rsa_crt_decrypt(sid_enc, p, q, d)

    @staticmethod
    def parse_private_key_blob(blob: bytes) -> tuple[int, int, int]:
        if len(blob) != KEY_BLOB_LEN:
            raise ValueError("bad private key blob length")

        p = bytes_to_long(blob[: P_LEN])
        q = bytes_to_long(blob[P_LEN : P_LEN + Q_LEN])
        d = bytes_to_long(blob[P_LEN + Q_LEN : P_LEN + Q_LEN + D_LEN])

        if p <= 1 or q <= 1 or d <= 1:
            raise ValueError("bad private key components")
        return p, q, d

    @staticmethod
    def rsa_crt_decrypt(ciphertext: bytes, p: int, q: int, d: int) -> bytes:
        ct = bytes_to_long(ciphertext)

        u = inverse(p, q)

        dp = d % (p - 1)
        dq = d % (q - 1)
        mp = pow(ct, dp, p)
        mq = pow(ct, dq, q)

        t = (mq - mp) % q
        h = (t * u) % q
        m = h * p + mp
        return long_to_bytes(m)


def encrypt_flag(p: int) -> tuple[bytes, bytes]:
    key = SHA256.new(long_to_bytes(p)).digest()
    iv = get_random_bytes(16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(FLAG, 16))
    return iv, ct

