
import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from tqdm import *

def walk_isogeny(E, exponent_vector):
    P = E.random_point()
    o = P.order()
    order = prod(ells[i] for i in range(len(ells)) if exponent_vector[i] == 1)
    while o % order:
        P = E.random_point()
        o = P.order()
    P = o // order * P
    phi = E.isogeny(P, algorithm='factored')
    E = phi.codomain()
    return E, phi


# CSIDH-512 prime
ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])

s = process(["sage", "chall.sage"])
# s = connect("lepton2.ctf.theromanxpl0.it", 7012)
# s.interactive()
# context.log_level = "DEBUG"
secret_vector = []

for i in trange(len(ells)):
    s.recvuntil(b": ")
    a2 = int(s.recvline().strip())
    s.recvline()
    # print(a2)
    E = EllipticCurve(F, [0, a2, 0, 1, 0])
    point = E.gen(0)
    point = (point.order() // ells[i]) * point
    s.sendline(f"{point.xy()[0]}, {point.xy()[1]}".encode())
    tmp = s.recvline()
    if b"Invalid" in tmp:
        secret_vector.append(0)
    else:
        secret_vector.append(1)
print(secret_vector)