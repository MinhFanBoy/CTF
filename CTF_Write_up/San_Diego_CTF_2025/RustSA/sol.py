
from Crypto.Util.number import *
n = 1 << 128
phi = 1 << 127
c = 187943791592623141370643984438525124469
e = 65537
d = pow(e, -1, phi)
print(long_to_bytes(pow(c, d, n)))