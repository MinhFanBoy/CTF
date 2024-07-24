from Crypto.Cipher import Salsa20
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
from secrets import token_bytes, token_hex
from zlib import crc32
from pwn import *

s = connect("tango.chal.imaginaryctf.org", 1337)
# s = process(["python3", "server.py"])
print(s.recvuntil(b"> "))
s.sendline(b"E")
s.sendline(b"sts")
s.recvuntil(b"Your encrypted packet is: ")
packet = s.recvline().strip().decode()
packet = bytes.fromhex(packet)
nonce = packet[:8]
checksum = bytes_to_long(packet[8:12])
ciphertext = packet[12:]

data = b'{"user":"root","command":"flag","nonce":""}'
checksum = long_to_bytes(crc32(data))
ciphertext = xor(ciphertext[:len(data)], data, b'{"user": "user", "command": "sts", "nonce": "f84c966c8519fd0f"}'[:len(data)])
packet = (nonce + checksum + ciphertext).hex()
print(s.recvuntil(b"> "))
s.sendline(b"R")
# print(s.recvline())
s.sendline(packet)
print(s.recvline())
