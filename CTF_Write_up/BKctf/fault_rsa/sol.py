
from Crypto.Util.number import *

c = 1094555114006097458981
e = 65537
n = 3367854845750390371489

p = 49450786403
q = 68105182763

assert p * q == n and isPrime(q) and isPrime(p)

d = pow(e, -1, (p - 1) * (q - 1))

flag = pow(c, d, n)

# BKSEC{*********}
    
# know + x = m (mod n)
know = bytes_to_long(b"BKSEC{\x00\x00\x00\x00\x00\x00\x00\x00\x00}")

bounds = know // n

for i in range(bounds - 256, bounds + 400):
    test = long_to_bytes(i * n + flag)
    if test.endswith(b"}") and test.startswith(b"BKSEC{"):
        print(f"Flag = {test}")

