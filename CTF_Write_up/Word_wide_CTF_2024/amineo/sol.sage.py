

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_0xffffffffffffffffffffffffffffff53 = Integer(0xffffffffffffffffffffffffffffff53); _sage_const_4 = Integer(4); _sage_const_3 = Integer(3); _sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_0 = Integer(0)
from secrets import randbits
from hashlib import sha256
import os


p = _sage_const_0xffffffffffffffffffffffffffffff53 
Nr = _sage_const_4 

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
    return bytes(x ** y for x, y in zip(a, b))
class Amineo:
    def __init__(self, nr):
        self.nr = nr
        self.k = pow(_sage_const_3 , -_sage_const_1 , p - _sage_const_1 )
    
    def H(self, S):
        x, y = S
        x += A*y**_sage_const_2 
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
print(enc.encrypt([x, _sage_const_0 ])[_sage_const_0 ])
