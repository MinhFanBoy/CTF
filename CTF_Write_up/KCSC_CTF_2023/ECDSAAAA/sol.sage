import os
from hashlib import sha3_512
from Crypto.Util.number import long_to_bytes, bytes_to_long
os.environ["TERM"] = "xterm-256color"

from pwn import *
from base64 import b64decode, b64encode
context.log_level = "debug"
s = remote("localhost", 60124)

msg = b""
data = b"Hi im Gan Dam"

s.sendline(msg)
s.recvuntil(b"Signature: ")
s.recvline().strip().decode()
s.sendline(data)
# payload = long_to_bytes(s_).zfill(32) + long_to_bytes(r_).zfill(32) 
payload = b"\x00" * 32 + b"\x00" * 32
payload = b64encode(payload).decode()
s.sendline(payload)
s.interactive()