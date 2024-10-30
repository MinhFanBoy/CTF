#!/usr/bin/env python
# coding: utf-8



from Crypto.Util.number import *
from secret import Curve,gx,gy

# flag = "hgame{" + hex(gx+gy)[2:] + "}"

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

c, d, p = Curve

G = (gx, gy)
P = (423323064726997230640834352892499067628999846, 44150133418579337991209313731867512059107422186218072084511769232282794765835)
Q = (1033433758780986378718784935633168786654735170, 2890573833121495534597689071280547153773878148499187840022524010636852499684)
S = (875772166783241503962848015336037891993605823, 51964088188556618695192753554835667051669568193048726314346516461990381874317)
T = (612403241107575741587390996773145537915088133, 64560350111660175566171189050923672010957086249856725096266944042789987443125)
assert ison(Curve, P) and ison(Curve, Q) and ison(Curve, G)
e = 0x10001
print(f"eG = {mul(Curve, G, e)}")

# eG = (40198712137747628410430624618331426343875490261805137714686326678112749070113, 65008030741966083441937593781739493959677657609550411222052299176801418887407)
