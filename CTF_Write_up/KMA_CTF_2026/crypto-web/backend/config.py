import os

FLAG = os.environ.get("FLAG", "LOCAL_TEST_FLAG").encode()

SALT = b"KMA2026"
PASSWORD = bytes.fromhex(os.environ.get("PASSWORD", "67676767676767676767676767676767"))
GCM_KEY = bytes.fromhex(os.environ.get("GCM_KEY", "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"))

if len(GCM_KEY) != 16:
    raise ValueError("GCM_KEY must be 16 bytes encoded as 32 hex characters")

GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16


ACCOUNT_ID_BYTES = 24
ACCOUNT_ID_MAX = 1 << (8 * ACCOUNT_ID_BYTES)
DEVICE_ID_BYTES = 24
DEVICE_ID_MAX = 1 << (8 * DEVICE_ID_BYTES)

P_LEN = 128
Q_LEN = 128
D_LEN = 256
BLOCK_SIZE = 16
KEY_BLOB_LEN = P_LEN + Q_LEN + D_LEN
RSA_BITS = 2048


SID_FIELD_BITS = 80
SID_FIELD_BYTES = 10
MIXED_FIELD_BYTES = 11
SID_TOTAL_BYTES = 240


MAX_LOGIN_ATTEMPTS = 1
MAX_PAYLOAD_HEX_CHARS = 20000

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "public"))
