import os

set_verbose(0)
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'linux'

from pwn import *
from gmpy2 import legendre
from Crypto.Util.number import *

s = process(["python3", "server.py"])

k = nextPrime(1 << (256 // 2 - 1))
# p = getPrime(256 // 2) * 2 + 1
# while not isPrime(p):
#     p = getPrime(256 // 2) * 2 + 1
# print(p)
# for i in range(1, 256000):
#     if (legendre(i, p) == 0):
#         print("ok", i)
#         break

# p = 15

# for i in range(1, p):
#     print(i, legendre(i, p))
