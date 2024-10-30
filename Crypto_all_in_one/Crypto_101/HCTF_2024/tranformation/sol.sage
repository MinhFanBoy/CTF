

from Crypto.Util.number import *
P = (423323064726997230640834352892499067628999846, 44150133418579337991209313731867512059107422186218072084511769232282794765835)
Q = (1033433758780986378718784935633168786654735170, 2890573833121495534597689071280547153773878148499187840022524010636852499684)
S = (875772166783241503962848015336037891993605823, 51964088188556618695192753554835667051669568193048726314346516461990381874317)
T = (612403241107575741587390996773145537915088133, 64560350111660175566171189050923672010957086249856725096266944042789987443125)
eG = (40198712137747628410430624618331426343875490261805137714686326678112749070113, 65008030741966083441937593781739493959677657609550411222052299176801418887407)
F.<c, d> = PolynomialRing(ZZ, 2)

lst = [P, Q, S, T]

eqs = [
    (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) for u, v in lst
]

I = F.ideal(eqs)
l = I.groebner_basis()

p = l[-1]
c_ = l[0].univariate_polynomial().change_ring(Zmod(p)).roots()[0][0]
d_ = l[1].univariate_polynomial().change_ring(Zmod(p)).roots()[0][0]

Curve = c_, d_, p 

def  twisted_Edwards_to_Montgomery(C):
    a, d, p = C
    A, B = (2 * (a + d) * pow(a - d, -1, p)) % p, (4 * pow(a - d, -1, p)) % p
    return (A, B, p)

def Montgomery_to_twisted_Edwards(C):
    A, B, p = C
    a, d = (A + 2) * pow(B, -1, p), (A - 2) * pow(B, -1, p)
    return (a, d, p)

def Montgomery_to_Short_Weierstrass(C):
    A, B, p = C
    a = (B ** 2) * (1 - A ** 2 * pow(3, -1, p)) % p
    b = B ** 3 * A * pow(3, -1, p) * (2 * A ** 2 * pow(9, -1, p) - 1) % p

    return a, b, p
"""
u**2 + v**2 - c**2 * (1 + d * u**2*v**2) = 0 mod p


u ^ 2 + v ^ 2 = c ^ 2 * (1 + d * u ^ 2 * v ^ 2) mod p

c ^ -2 * (u ^ 2 + v ^ 2) = 1 + d * u ^ 2 * v ^ 2 mod p

want c ^ -2 * (u ^ 2 + v ^ 2) = (1 + d * u ^ 2 * v ^ 2) = a * u ^ 2 + * v ^ 2 mod p

a = 
"""
def ison(C, P):
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0
def add(C, P, Q):
    c, d, p = C
    u1, v1 = P
    u2, v2 = Q
    assert ison(C, P) and ison(C, Q)
    u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p
    v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p
    return (int(u3), int(v3))

def mul(C, P, m):
    assert ison(C, P)
    c, d, p = C
    B = bin(m)[2:]
    l = len(B)
    u, v = P
    PP = (-u, v)
    O = add(C, P, PP)
    Q = O
    if m == 0:
        return O
    elif m == 1:
        return P
    else:
        for _ in range(l-1):
            P = add(C, P, P)
        m = m - 2**(l-1)
        Q, P = P, (u, v)
        return add(C, Q, mul(C, P, m))
e = 0x10001
c = c_
d = d_

aa = 1
dd = (d * c ** 4) % p

C_ = twisted_Edwards_to_Montgomery((aa, dd, p))
a, b, _ = Montgomery_to_Short_Weierstrass(C_)
k = EllipticCurve(Zmod(p), [a, b]).order()
k = pow(e, -1, k)
G = mul(Curve, eG, k)
print(G)
assert (mul(Curve, G, e)==eG)
flag = "hgame{" + hex(G[0]+G[1])[2:] + "}"
print(flag)