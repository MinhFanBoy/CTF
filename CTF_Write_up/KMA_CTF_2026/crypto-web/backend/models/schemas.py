from dataclasses import dataclass


@dataclass
class LoginSession:
    sid_enc: bytes
    sid_plain: bytes
    iv: bytes
    encrypted_flag: bytes


@dataclass
class ApiError(Exception):
    message: str
    status_code: int = 400
