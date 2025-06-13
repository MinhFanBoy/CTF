#!/usr/bin/env sage
import os, json
from hashlib import md5
from Crypto.Cipher import DES
os.environ["TERM"] = "linux"
from pwn import *
from Crypto.Util.number import *

context.log_level = "debug"
def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)
        
P = ComplexField(128)

F = PolynomialRing(ZZ, 'x', 16)
xs = list(F.gens())

def encode(data):
    P.<x> = ComplexField(128)[]
    poly = 0
    for i in range(len(data)):
        poly += data[i] * x ^ i
    print(poly)
    return poly.roots()[1][0]

s = process(['sage', 'chal.sage'])

s.sendline(json.dumps({"option": "get_secret"}))

output1 = eval(s.recvline().decode())

def gen_rand(user_seed, server_seed):
    return DES.new(user_seed + server_seed, DES.MODE_ECB).encrypt(b"\x00" * 16)

def xor(data, key):
    from itertools import cycle
    if len(key) > len(data):
        key = data, data = key
    cycled_key = cycle(key)
    return bytes([b ^^ next(cycled_key) for b in data])


i = P(output1['encoded_secret'])
print(output1["user_seed"])
key = xor(bytes.fromhex(output1["user_seed"]), b"\x01")

s.sendline(json.dumps({"option": "encode", "data": '01' * 15 + '00', "user_seed": (key).hex()}))

output2 = eval(s.recvline().decode())

i -= P(output2["encoded_data"]) - encode(bytes.fromhex('01' * 15 + '00'))


def encode2(i):
    poly = sum(xs[k] * (i) ** k for k in range(16))
    return poly

eqs = []
eq1, eq2 = [], []
ss = [var('s' + str(i)) for i in range(16)]
for i, _ in enumerate((encode2(i)).coefficients()):
    eq1.append((QQ(_.real_part()) ))
    eq2.append((QQ(_.imag_part()) ))
eqs.append(eq1)
eqs.append(eq2)

M = diagonal_matrix([1/(1 << 128)] * 16)
M = block_matrix(QQ,
    [
        [matrix(eqs).T, M]
     ]
)

M = M.LLL()
M *= (1 << 128)

k = (bytes(list(M[0][2:] * sign(M[0][-1]))))
s.sendline(json.dumps({"option": "verify", "user_secret": k.hex()}))
s.interactive()