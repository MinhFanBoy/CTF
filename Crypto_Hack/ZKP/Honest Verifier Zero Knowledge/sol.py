

import os
import random
from Crypto.Util.number import *

from pwn import *
from json import *

s = connect("socket.cryptohack.org", 13427)

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

"""
f = flag

y = g ^ f

e: random
a, z: choice

g ^ z = a * y ^ e
z = 0
"""

print(s.recvline())
pub = loads(s.recvline())

y = pub["y"]
e = pub["e"]
s.sendline(dumps({"a" : pow(pow(y, e, p), -1, p), "z" : 0}).encode())
print(s.recvline())
# z_1 = loads(s.recvline())["z"]