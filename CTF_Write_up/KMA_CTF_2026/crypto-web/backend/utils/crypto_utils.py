from Crypto.Hash import SHA256
import hmac

def safe_hex_to_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except Exception:
        raise ValueError("invalid hex")

def constant_time_bytes_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def i2b(x: int, length: int) -> bytes:
    return int(x).to_bytes(length, "big")


def b2i(data: bytes) -> int:
    return int.from_bytes(data, "big")


def sha256(data: bytes) -> bytes:
    return SHA256.new(data).digest()


def split_blocks(data_hex: str, block_size: int = 16) -> list[str]:
    raw = bytes.fromhex(data_hex)
    return [raw[i:i + block_size].hex() for i in range(0, len(raw), block_size)]
