
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

# s = process(["sage", "chall.sage"])
# s = connect("lepton2.ctf.theromanxpl0.it", 7012)
# s.interactive()
# context.log_level = "DEBUG"
secret_vector = []

# s.recvuntil(b": ")
# a2 = int(s.recvline().strip())
# s.recvline()
# print(a2)
a2 = 1217516833571330343353898935993421410539647360360690110607250780107133069394060364841341885603914921311697197384093195276223473276766743593374481192025710
E = EllipticCurve(F, [0, a2, 0, 1, 0])
# point = E.gen(0)
# point = (point.order() // 3) * point
# s.sendline(f"{point.xy()[0]}, {point.xy()[1]}".encode())
# # s.interactive()

# from hashlib import sha256
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad

# secret_key = sha256(b"0").digest()
# cipher = AES.new(secret_key, AES.MODE_ECB)
# print(cipher.decrypt(bytes.fromhex("4be718c8a05fb07609b1344cc6771e95")))
# s.interactive()

# P,Q = E.torsion_basis(3)
# print(P)
# print(Q)
from sage.schemes.elliptic_curves.ell_field import *
# EE = (compute_model(E, 'short_weierstrass'))
# print(EE)
# P,Q = EE.torsion_basis(3)
# print(P)
# print(Q)
while True:
    P = E.random_point()
    P_order = P.order()
    if P_order % 9 == 0:
        P_6torsion = (P_order // 9) * P
        if P_6torsion.order() == 9:
            # Đây là điểm 6-torsion4
            print(P_6torsion)
            x, y = P_6torsion.xy()
            print(f"{x}, {y}")
            break