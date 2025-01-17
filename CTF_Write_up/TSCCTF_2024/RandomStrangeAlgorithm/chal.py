import secrets
import os
from Crypto.Util.number import bytes_to_long, isPrime

def genPrime():
    while True:
        x = secrets.randbelow(1000000)
        if isPrime(2**x - 1):
            return x


p = genPrime()
q = genPrime()

M = (1 << p + q) - 1
flag = os.getenv("FLAG") or "FLAG{test_flag}"
flag = bytes_to_long(flag.encode())
e = 65537

def weird(x, e, p, q, M):
    res = 1
    strange = lambda x, y: x + (y << p) + (y << q) - y
    for b in reversed(bin(e)[2:]):
        if b == "1":
            res = res * x
            res = strange(res & M, res >> (p + q))
            res = strange(res & M, res >> (p + q))
            res = strange(res & M, res >> (p + q))
        x = x * x
        x = strange(x & M, x >> (p + q))
        x = strange(x & M, x >> (p + q))
        x = strange(x & M, x >> (p + q))
    return res

ct = weird(flag, e, p, q, M)

print(f"Cipher: {hex(ct)}")