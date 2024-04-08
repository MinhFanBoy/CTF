
from Crypto.Util.number import *
from tqdm import *
from Crypto.PublicKey import RSA

a = open("truncated-2/public.pem", "r").read()
enc = bytes_to_long(open('truncated-2/flag.txt.enc', 'rb').read())

tmp = RSA.import_key(a)
n = tmp.n
e = 65537
dp = int("4894e9fa2c26b0e1c631ced2f86be0207a82751d707b018839565e93f551df596e9d16f05599a2bfb0bbb300064139f383de85c793e058da2cce41a9a0398e40be05bb9b82703fe804164f5ff4d76623d0e4c720fd705ce6eface979489a8b3a2bd6630077699c0aa8da6250c1de8840d3e5afc34db865e0650ce08f828b49ad", 16)
r = 2
temp = pow(r, e*dp, n) - r
p = GCD(temp, n)
q = n // p
assert p*q == n
flag = long_to_bytes(pow(enc, inverse(e, (p-1)*(q-1)), n))
print(flag)
