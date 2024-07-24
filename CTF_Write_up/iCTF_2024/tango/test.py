from Crypto.Cipher import Salsa20
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
from secrets import token_bytes, token_hex
from zlib import crc32
from pwn import *

# from secret import FLAG

KEY = token_bytes(32)

nonce = b"\x00" * 8

# cipher = Salsa20.new(key=KEY, nonce=nonce)

# data = json.dumps({'user': 'user', 'command': 'sts', 'nonce': token_hex(8)}).encode('ascii')
# checksum = long_to_bytes(crc32(data))
# ciphertext = cipher.encrypt(b"\x00" * 32)
# print(ciphertext)
# print('Your encrypted packet is:', (nonce + checksum + ciphertext).hex())

cipher = Salsa20.new(key=KEY, nonce=nonce)

data = b'{"user":"root","command":"flag","nonce":""}'
# checksum = long_to_bytes(crc32(data))
ciphertext = cipher.encrypt(data)
# print(xor(ciphertext[0:8], data[0:8]))
# print(xor(ciphertext[8:16], data[8:16]))
cipher = Salsa20.new(key=KEY, nonce=nonce)
print(cipher.decrypt(ciphertext))