
from pwn import *
from Crypto.Util.number import *
from sage.all import *

# s = process(["python3", "task.py"])
# s = connect("0.0.0.0", 1338)
# context.log_level = "debug"

payload = [
    b"\x00" * 42,
    b"\x00" * 41 + b"\x80",
    b"\x00" * 41 + b"\x01",
    b"DubheCTF{" + b"\x00" * 32 + b"}"
]

s = process(["python3", "task.py"])
out = []
for i in range(4):
    s.recvuntil(b'3.exit\n')
    s.sendline(b"1")
    s.sendline(payload[i].hex())
    out.append(bytes.fromhex(s.recvline().split(b":")[1].strip().decode()))

s.recvuntil(b'3.exit\n')
s.sendline(b"2")
c = bytes.fromhex(s.recvline().split(b":")[1].strip().decode())
out = [bytes_to_long(i) for i in out]
c = bytes_to_long(c)
payload = [int.from_bytes(i, 'little') for i in payload]

FF = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
F = GF(2)["x"]
x = F.gen()
def i2p(p):
    return F(Integer(p).bits())

def p2i(p):
    return Integer(p.list(), 2)

def rev(p, n):
    p = (p.list() + [0] * n)[:n]
    return F(p[::-1])

t1 = rev(i2p(out[0]), 256) -rev(i2p(payload[0]), 42 * 8) * (x ** 256) - rev(i2p(FF), 256) *(1 + x ** (42 * 8))
t2 = rev(i2p(out[1]), 256) -rev(i2p(payload[1]), 42 * 8) * (x ** 256) - rev(i2p(FF), 256) *(1 + x ** (42 * 8))
t3 = rev(i2p(out[2]), 256) -rev(i2p(payload[2]), 42 * 8) * (x ** 256) - rev(i2p(FF), 256) *(1 + x ** (42 * 8))
t4 = rev(i2p(out[3]), 256) -rev(i2p(payload[3]), 42 * 8) * (x ** 256) - rev(i2p(FF), 256) *(1 + x ** (42 * 8))

G1 = gcd(t1 - t2, t1 - t3)
G2 = gcd(t1 - t2, t1 - t4)
print(G1 == G2)
K = GF(2**256, "a",modulus = G1)

# Y = K(rev(i2p(out[0]), 256) + rev(i2p(c), 256)) / K(x ** (256)) -K(rev(i2p(payload[0]), 42 * 8)) 
# print(long_to_bytes(int(Integer(K(Y).list(), 2))))



def int2poly(n, padlen=256):
    return K(ZZ(n).digits(base=2, padto=padlen)[::-1])

def poly2int(p, padlen=256):
    L = p.list()
    L += [0] * (padlen - len(L))
    return int(ZZ(L[::-1], base=2))

tmp = K(((int2poly(out[3]) - int2poly(c)) / K(x ** (256 + 8))) % G1)
print(long_to_bytes(poly2int(tmp, 256))[::-1])
