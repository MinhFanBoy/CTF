
from secrets import randbits
from hashlib import sha256
import os


p = 0xffffffffffffffffffffffffffffff53
Nr = 4

bSEED = b"AMINEO"
A = int.from_bytes(sha256(b"A" + bSEED).digest(), "big") % p
B = int.from_bytes(sha256(b"B" + bSEED).digest(), "big") % p

Ci = [int.from_bytes(sha256(b"C" + bSEED + str(r).encode()).digest(), "big") % p for r in range(Nr)]
Di = [int.from_bytes(sha256(b"D" + bSEED + str(r).encode()).digest(), "big") % p for r in range(Nr)]
Ei = [int.from_bytes(sha256(b"E" + bSEED + str(r).encode()).digest(), "big") % p for r in range(Nr)]
Fi = [int.from_bytes(sha256(b"F" + bSEED + str(r).encode()).digest(), "big") % p for r in range(Nr)]
Gi = [int.from_bytes(sha256(b"G" + bSEED + str(r).encode()).digest(), "big") % p for r in range(Nr)]
Hi = [int.from_bytes(sha256(b"H" + bSEED + str(r).encode()).digest(), "big") % p for r in range(Nr)]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
class Amineo:
    def __init__(self, nr):
        self.nr = nr
        self.k = pow(3, -1, p - 1)
    
    def H(self, S):
        x, y = S
        x += A*y**2
        y += pow(x, self.k)
        x += B*y

        return x, y

    def M(self, S, r):
        x, y = S
        return Ci[r]*x + Di[r]*y + Ei[r], Fi[r]*x + Gi[r]*y + Hi[r]

    def encrypt(self, S):
        Se = S.copy()
        for r in range(self.nr):
            Se = self.H(self.M(Se, r))

        return list(Se)
enc = Amineo(Nr)
# F.<x, y> = PolynomialRing(Zmod(p))
var("x y")
print(enc.encrypt([x, 0])[0])