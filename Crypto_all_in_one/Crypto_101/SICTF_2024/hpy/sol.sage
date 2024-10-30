
from Crypto.Util.number import *

P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
mP = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
mQ = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933) 

F.<c, d> = PolynomialRing(ZZ, 2)

lst = [P, Q, mP, mQ]

eqs = [
    (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) for u, v in lst
]

I = F.ideal(eqs)
l = I.groebner_basis()

p = max(i for (i, j) in factor(l[-1], 2 ** 20))
c_ = (- sqrt(- (l[0].univariate_polynomial().change_ring(Zmod(p)).coefficients()[0] ) % p) % p)
d_ = (- (l[1].univariate_polynomial().change_ring(Zmod(p)).coefficients()[0] ) % p)

def twisted_Edwards_to_Montgomery(C):
    a, d, p = C
    A, B = (2 * (a + d) * pow(a - d, -1, p)) % p, (4 * pow(a - d, -1, p)) % p
    return (A, B, p)

def Montgomery_to_twisted_Edwards(C):
    A, B, p = C
    a, d = (A + 2) * pow(B, -1, p), (A - 2) * pow(B, -1, p)
    return (a, d, p)

def Montgomery_to_Short_Weierstrass(C):
    A, B, p = C
    # a = pow((B ** 2) * (1 - A ** 2 * pow(3, -1, p)), -1, p)
    # b = A * pow(B ** 3 * A * pow(3, -1, p) * (2 * A ** 2 * pow(9, -1, p) - 1), -1, p)
    a = ((3 - A ** 2) * pow(3 * B ** 2, -1, p)) % p
    b = ((2 * (A ** 3) - 9 * A) * pow(27 * B ** 3, -1, p)) % p
    return a, b, p

def change_point_from_twisted_Edwards_to_Montgomery(P, C):
    a, d, p = C
    u, v = P
    x_, y_ = ((1 + v) * pow(1 - v, -1, p)) % p, ((1 + v) * pow((1 - v) * u, -1, p) % p) % p
    return int(x_) % p, int(y_) % p

def change_point_from_Montgomery_to_Short_Weierstrass(P, C):
    A, B, p = C
    x, y = P
    x_, y_ = ((x + A * pow(3, -1, p)) * pow(B, -1, p)) % p, (y * pow(B, -1, p)) % p
    return int(x_) % p, int(y_) % p

def is_on_twisted_Edwards(P, C):

    u, v = P
    a, d, p = C
    
    # Tính vế trái: au^2 + v^2
    left = (a * pow(u, 2, p) + pow(v, 2, p)) % p
    
    # Tính vế phải: 1 + du^2v^2
    right = (1 + d * pow(u, 2, p) * pow(v, 2, p)) % p
    
    return left - right

def is_on_Montgomery(P, C):

    x, y = P
    A, B, p = C

    left = (B * pow(y, 2, p)) % p

    right = (pow(x, 3, p) + A * pow(x, 2, p) + x) % p
    
    return left - right

def is_on_Short_Weierstrass(P, C):

    x, y = P
    a, b, p = C
    
    left = pow(y, 2, p)
    right = (pow(x, 3, p) + a * x + b) % p
    
    return left - right

p = 903968861315877429495243431349919213155709
c = 662698094423288904843781932253259903384619 # or p - c
d = 540431316779988345188678880301417602675534

Curve = 1, (d * pow(c, 4, p)), p 
M = twisted_Edwards_to_Montgomery(Curve)
W = Montgomery_to_Short_Weierstrass(M)
E = EllipticCurve(GF(p), W[:2])
P, Q, mP, mQ = [((i[0] * pow(c, -1, p)) % p, (i[1] * pow(c, -1, p)) % p) for i in (P, Q, mP, mQ)]
# print(is_on_twisted_Edwards(P, Curve), is_on_twisted_Edwards(Q, Curve), is_on_twisted_Edwards(mP, Curve), is_on_twisted_Edwards(mQ, Curve))

P = change_point_from_twisted_Edwards_to_Montgomery(P, Curve)
Q = change_point_from_twisted_Edwards_to_Montgomery(Q, Curve)
mP = change_point_from_twisted_Edwards_to_Montgomery(mP, Curve)
mQ = change_point_from_twisted_Edwards_to_Montgomery(mQ, Curve)

# print(is_on_Montgomery(P, M), is_on_Montgomery(Q, M), is_on_Montgomery(mP, M), is_on_Montgomery(mQ, M))
P = change_point_from_Montgomery_to_Short_Weierstrass(P, M)
Q = change_point_from_Montgomery_to_Short_Weierstrass(Q, M)
mP = change_point_from_Montgomery_to_Short_Weierstrass(mP, M)
mQ = change_point_from_Montgomery_to_Short_Weierstrass(mQ, M)

P = E(P)
Q = E(Q)
mP = E(mP)
mQ = E(mQ)

m1 = int(discrete_log(mP, P, operation = "+"))
m2 = int(discrete_log(mQ, Q, operation = "+"))
print(long_to_bytes(m1) + long_to_bytes(m2))
