
#!/usr/bin/env python

from pwn import *
from Crypto.Util.number import *
from sage.all import *

# context.log_level = "debug"

x = GF(2)["x"].gen()
gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)
h = gf2e["h"].gen()

def xor(b1,b2):
    return bytes([i^j for i,j in zip(b1,b2)])

# Converts an integer to a gf2e element, little endian.
def _to_gf2e(n):
    return gf2e([(n >> i) & 1 for i in range(127, -1, -1)])


# Converts a gf2e element to an integer, little endian.
def _from_gf2e(p):
    n = p.integer_representation()
    ans = 0
    for i in range(128):
        ans <<= 1
        ans |= ((n >> i) & 1)
    return int(ans)

def find_key(t1, t2, m1, m2):
    f = h ** 2 - (_to_gf2e(int.from_bytes(t1, byteorder="big")) + _to_gf2e(int.from_bytes(t2, byteorder="big"))) / (_to_gf2e(int.from_bytes(m1, byteorder="big")) + _to_gf2e(int.from_bytes(m2, byteorder="big")))
    H = f.roots()[0][0]
    return H

"""


((A * H + C_1) * H + L) * H + S = Tag 

with A = 0
so: ((C_1) * H + L) * H + S = Tag 

-> C_1 * H^2 + L * H + S = Tag

"""

# s = connect("dualsummon.chal.seccon.jp", 18373)
s = process(["python3", "server.py"])

def get_encrypt(number, pt):
    s.sendlineafter(b"[1] summon, [2] dual summon >", b"1")
    s.recvuntil(b"summon number (1 or 2) >")
    s.sendline(number)
    s.recvuntil(b"name of sacrifice (hex) >")
    s.sendline(pt.hex())
    s.recvline()
    tag = bytes.fromhex(s.recvline().split(b"=")[1].strip().decode('utf-8'))
    return tag

m1 = b"\x00" * 16
m2 = b"\x00" * 15 + b"\x01"
m1 = b"a"*16
m2 = b"a"*15 + b"b"

t1 = get_encrypt(b"1", m1)
t2 = get_encrypt(b"1", m2)
t3 = get_encrypt(b"2", m1)
t4 = get_encrypt(b"2", m2)

H_1 = find_key(t1, t2, m1, m2)
H_2 = find_key(t3, t4, m1, m2)

L = _to_gf2e(((8 * 0) << 64) | (8 * 16))

M_1 = _to_gf2e(int.from_bytes(m1, byteorder="big"))
M_2 = _to_gf2e(int.from_bytes(m2, byteorder="big"))


Tag_1 = _to_gf2e(int.from_bytes(t1, byteorder="big"))
Tag_2 = _to_gf2e(int.from_bytes(t4, byteorder="big"))

m = _from_gf2e((M_1  * H_1 * H_1 + M_2 * H_2 * H_2 + Tag_1 + Tag_2) / (H_1 * H_1 + H_2 * H_2))


s.recvuntil(b">") 
s.sendline(b"2") # dual summon
s.recvuntil(b">") 
s.sendline(long_to_bytes(m).hex())
s.interactive()