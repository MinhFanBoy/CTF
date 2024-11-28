from sage.all import *
from secret import flag
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime
from random import getrandbits


p = getPrime(256)
G = Zmod(p**3)
M = Matrix(G,[G.random_element() for i in range(64)],ncols=8)
a = getrandbits(590)
b = getrandbits(590)
S = M ** (a * b)


key = sha256(S.str().encode()).digest()
ct = AES.new(key, AES.MODE_ECB).encrypt(pad(flag, 16)).hex()


with open("output", "w") as f:
    f.write('p = ' + str(p) + '\n')
    f.write('M = ' + str(list(M)) + '\n')
    f.write('Ma =' + str(list(M**a)) + '\n')
    f.write('Mb = ' + str(list(M**b)) + '\n')
    f.write('ct = 0x' + ct)