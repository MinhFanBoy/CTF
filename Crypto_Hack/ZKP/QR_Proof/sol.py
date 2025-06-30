

from Crypto.Util.number import *

from pwn import *
from json import *


p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617

"""
Task1:

a0, a1: choice
s : random
e0, e1, z0, z1: choice
e0 ^ e1 = s
g ^ z0 = a0 * y0 ^ e0 = a0 * g ^ (w * e0)
g ^ z1 = a1 * y1 ^ e1

a0 = a1 = 1
z1 = 0, a1 = 1, e1 = 0
e0 = e1 ^ s = s
z0 = w0 * e0


Task2:


w0, w1: random
y0, y1: random, known = g ^ w0, g ^ w1

r0: random
a0: random = g ^ r0
e1: random
z1: random
a1 = y1 ^ -e1 * g ^ z1
s: random
e0 = s ^ e1
z0 = r0 + e0 * w0
s2: random
e2 = s2 ^ e1
z2 = r0 + e2 * w0

Task 3:

w0, w1: random
y0, y1 = g ^ w0, g ^ w1: known
s: random
a0, a1, e0, e1, z0, z1: choice

e0 ^ e1 = s
g ^ z0 = a0 * y0 ^ e0 = a0 * g ^ (w0 * e0)
g ^ z1 = a1 * y1 ^ e1 = a1 * g ^ (w1 * e1)

z0 = 0, a0 = 1, e0 = 0
e1 = s, z1 = 0, a1 = 1 / y1 ^ s
"""

s = connect("archive.cryptohack.org", 11840)

# Part 1

a0 = a1 = 1

s.sendlineafter("a0:", str(a0).encode())
s.sendlineafter("a1:", str(a1).encode())
s.recvuntil(b"s = ")
secret = int(s.recvline().strip())

z1 = 0
e1 = 0
e0 = e1 ^ secret
z0 = w0 * e0
s.sendlineafter("e0:", str(e0).encode())
s.sendlineafter("e1:", str(e1).encode())
s.sendlineafter("z0:", str(z0).encode())
s.sendlineafter("z1:", str(z1).encode())

# Part 2

s.recvuntil(b"a0 = ")
a0 = int(s.recvline().strip())
s.recvuntil(b"a1 = ")
a1 = int(s.recvline().strip())
s.recvuntil(b"s = ")
secret = int(s.recvline().strip())
s.recvuntil(b"e0 = ")
e0 = int(s.recvline().strip())
s.recvuntil(b"e1 = ")
e1 = int(s.recvline().strip())
s.recvuntil(b"z0 = ")
z0 = int(s.recvline().strip())
s.recvuntil(b"z1 = ")
z1 = int(s.recvline().strip())

s.recvuntil(b"a0 = ")
a0 = int(s.recvline().strip())
s.recvuntil(b"a1 = ")
a1 = int(s.recvline().strip())
s.recvuntil(b"s* = ")
secret_ = int(s.recvline().strip())
s.recvuntil(b"e0* = ")
e0_ = int(s.recvline().strip())
s.recvuntil(b"e1* = ")
e1_ = int(s.recvline().strip())
s.recvuntil(b"z0* = ")
z0_ = int(s.recvline().strip())
s.recvuntil(b"z1* = ")
z1_ = int(s.recvline().strip())

"""

z2 = r0 + e2 * w0

(z1 - z2) = w0 * (e1 - e2)
w0 = (z1 - z2) * pow(e1 - e2, -1, q) % q

"""

w0 = (z1 - z1_) * pow(e1 - e1_, -1, q) % q
s.sendlineafter("witness!", str(w0).encode())

# Part 3

s.recvuntil(b"y0 = ")
y0 = int(s.recvline().strip())
s.recvuntil(b"y1 = ")
y1 = int(s.recvline().strip())
s.recvuntil(b"s = ")
secret = int(s.recvline().strip())

z0 = 0
a0 = 1
e0 = 0
e1 = secret
z1 = 0
a1 = pow(pow(y1, secret, p), -1, p)

s.sendlineafter(b"a0: ", str(a0).encode())
s.sendlineafter(b"a1: ", str(a1).encode())
s.sendlineafter(b"e0: ", str(e0).encode())
s.sendlineafter(b"e1: ", str(e1).encode())
s.sendlineafter(b"z0: ", str(z0).encode())
s.sendlineafter(b"z1: ", str(z1).encode())

s.interactive()