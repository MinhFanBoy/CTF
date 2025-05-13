import os
from Crypto.Util.number import bytes_to_long, getPrime

#p = getPrime(64)
p = 12267883553178394373
Fp = GF((p, 3))

FLAG = b'KMACTF{fake_flag}'

s = Fp.from_integer(bytes_to_long(FLAG))

set_random_seed(1337)

out = []
for i in range(15):
    a, b = Fp.random_element(), Fp.random_element()
    s = a * s + b
    out.extend(s)

print([x >> 57 for x in out])
[43, 80, 59, 18, 3, 12, 77, 20, 25, 68, 68, 30, 47, 73, 78, 52, 62, 68, 84, 39, 32, 16, 1, 55, 39, 58, 48, 8, 72, 13, 63, 34, 19, 44, 45, 56, 82, 76, 10, 46, 69, 28, 69, 78, 29]