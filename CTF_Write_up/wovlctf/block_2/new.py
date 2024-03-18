

import random
import secrets
import sys
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor


MASTER_KEY = secrets.token_bytes(16)

message = pad(b"KCSCLMAOYXJZQKqqqqqqqqqqqqqqqqqqqZQ", 16)

iv = secrets.token_bytes(16)
cipher = AES.new(MASTER_KEY, AES.MODE_ECB)
blocks = [message[i:i+16] for i in range(0, len(message), 16)]

# encrypt all the blocks
encrypted = [cipher.encrypt(b) for b in [iv, *blocks]]
print(encrypted)
# xor with the next block of plaintext
for i in range(len(encrypted) - 1):
    encrypted[i] = strxor(encrypted[i], blocks[i])
print(iv + b''.join(encrypted))

