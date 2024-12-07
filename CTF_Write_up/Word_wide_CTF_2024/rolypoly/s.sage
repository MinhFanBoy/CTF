from sage.all import GF, PolynomialRing, ZZ, save
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.number import *

n = 1201
q = 467424413

K = GF(q)
PR = PolynomialRing(K, names=('t',)); (t,) = PR._first_ngens(1)
R = PR.quotient(PR.ideal([t**n-1 ]))
PR2 = PolynomialRing(R,2 , names=('x', 'y',)); (x, y,) = PR2._first_ngens(2)

def SamplePoly():
    p = R.zero()
    for i in range(0,n):
        p += ZZ.random_element(0,q)*t**i
    return p

def SampleSmallPoly():
    sp = R.zero()
    for i in range(0,n):
        sp += ZZ.random_element(0,4)*t**i
    return sp

def r2int(r):
    out = 1
    for ri in r.coefficients():
        out *= int(sum([j for j in ri.lift().coefficients()]))
    return out

def keyGen():
    ux = SampleSmallPoly()
    uy = SampleSmallPoly()
    X10 = SamplePoly()
    X01 = SamplePoly()
    X00 = -X10*ux - X01*uy
    return (ux,uy,X00,X10,X01)

def Encrypt(m, key):
    _,_,X00,X10,X01 = key
    Ctx = X00 + X10*x + X01*y
    # print(Ctx)
    r = SamplePoly() + SamplePoly()*x + SamplePoly()*y
    Ctx = Ctx*r
    for i in range(0,3):
        for j in range(0,3-i):
            Ctx += 4*SampleSmallPoly()*x**i*y**j
    return (Ctx + m, r)

k = (keyGen())
m = bytes_to_long(b"lll")
# print(k)
lll= (Encrypt(m, k))
# print(lll[0])
# print(lll[0](tbar = 1))
print(lll[1])