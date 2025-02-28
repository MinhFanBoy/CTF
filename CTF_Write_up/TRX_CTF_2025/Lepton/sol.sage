
# from hashlib import sha256
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad

# # CSIDH-512 prime
# ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 
#         71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 
#         149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 
#         227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
#         307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
# p = 4 * prod(ells) - 1
# F = GF(p)
# E0 = EllipticCurve(F, [1, 0])
# print(E0)
# secret_vector = [randint(0, 1) for _ in range(len(ells))]

# # with open('flag.txt', 'r') as f:
# #     FLAG = f.read().strip()
# FLAG = "TRX{??????????????????????}"
# def walk_isogeny(E, exponent_vector):
#     P = E.random_point()
#     o = P.order()
#     order = prod(ells[i] for i in range(len(ells)) if exponent_vector[i] == 1)
#     while o % order:
#         P = E.random_point()
#         o = P.order()
#     P = o // order * P
#     phi = E.isogeny(P, algorithm='factored')
#     E = phi.codomain()
#     return E, phi


# E = E0
# phi = E.identity_morphism()
# print(f"{phi = }")
# random_vector = [randint(0, 1) for _ in range(len(ells))]
# E, _ = walk_isogeny(E, random_vector)
# print(f"{E, _ = }")
# E = E.montgomery_model()
# print(f"{E, _ = }")
# E.set_order(4 * prod(ells))
# print("[>] Intermidiate montgomery curve:", E.a2())
# print("[?] Send me your point on the curve")
# try:
#     P = E([int(x) for x in input().split(",")])
#     E, phi = walk_isogeny(E, secret_vector)
#     E_final = E.montgomery_model()
#     phi = E.isomorphism_to(E_final)*phi
#     Q = phi(P)
#     print(Q.xy())
#     secret_key = sha256(str(Q.xy()[0]).encode()).digest()
#     cipher = AES.new(secret_key, AES.MODE_ECB)
#     print(cipher.encrypt(pad(FLAG.encode(), 16)).hex())
# except:
#     print("[!] Invalid input")
#     pass

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

secret_key = sha256(b"0").digest()
cipher = AES.new(secret_key, AES.MODE_ECB)
print(cipher.decrypt(bytes.fromhex("3a641a40286eb1611870ca1a8609689793153b1f404037d202b36969d18e2bb61f6ff9e2fc12142c1a53e01f7f17dc17")))