import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
from Crypto.Util.number import *

g = 0xcd8da4ff37e45ec3
FF = 0xffffffffffffffff
n = 64

R.<x> = GF(2)['x']

def i2p(p):
    return R(Integer(p).bits())

def p2i(p):
    return Integer(p.list(), 2)

def rev(p, n):
    p = (p.list() + [0] * n)[:n]
    return R(p[::-1])

poly = rev(i2p(g), 64) + x**64

K = GF(2**64, "x",modulus = poly)
x = K.gens()[0]

def int2poly(p, n = 64):
    p = K(Integer(p).bits())
    p = (p.list() + [0] * n)[:n]
    return K(p[::-1])

def poly2int(p, padlen=64):
    L = p.list()
    L += [0] * (padlen - len(L))
    return int(ZZ(L[::-1], base=2))

def attack(hint, data, k):
    hint = int2poly(hint)
    I = int2poly(FF ^^ k)
    Y = int2poly(FF)
    Z = int2poly(0 ^^ FF)
    b = len(data)*8
    M1 = int2poly(int.from_bytes(data, 'little'), b)

    f = hint - (M1 * x ^ n + Y + Z)
    f = (f/ (x^b)) - Y
    f = f + Y

    I2 = int2poly(FF ^^ k)
    b2 = 8 * 8
    f = (f - ((Y + I2) * x ^ b2 + Y + Z))/(x^n)

    return long_to_bytes(poly2int(f))[::-1]

def attack2(data):
    Y = int2poly(FF)
    b = len(data)*8
    M1 = int2poly(int.from_bytes(data, 'little'), b)

    I = (M1 * x ^ n - Y * x^b - Y) / (x^b + 1)
    code = poly2int(I) ^^ FF
    return code


s = process(["python3", "chall.py"])

context.log_level = "debug"
s.sendline(b"H")
s.recvuntil(b"hint: ")

hint = int(s.recvline().strip(), 16)

data = attack(hint, b"hint", 0)
code = attack2(data)

s.sendline(b"A")
s.sendline(hex(code)[2:].encode())

s.interactive()