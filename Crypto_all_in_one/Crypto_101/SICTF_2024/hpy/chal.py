#user:mumu666

from Crypto.Util.number import *
from secret import flag, Curve

def happy(C, P):
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0

def new(C, P, Q):
    c, d, p = C
    u1, v1 = P
    u2, v2 = Q
    assert happy(C, P) and happy(C, Q)
    u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p
    v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p
    return (int(u3), int(v3))

def year(C, P, m):
    assert happy(C, P)
    c, d, p = C
    B = bin(m)[2:]
    l = len(B)
    u, v = P
    PP = (-u, v)
    O = new(C, P, PP)
    Q = O
    if m == 0:
        return O
    elif m == 1:
        return P
    else:
        for _ in range(l-1):
            P = new(C, P, P)
        m = m - 2**(l-1)
        Q, P = P, (u, v)
        return new(C, Q, year(C, P, m))

c, d, p = Curve

flag = flag.lstrip(b'SICTF{').rstrip(b'}')
l = len(flag)
l_flag, r_flag = flag[:l // 2], flag[l // 2:]

m1, m2 = bytes_to_long(l_flag), bytes_to_long(r_flag)
assert m1 < p and m2 < p

P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)

print(f'happy(C, P) = {happy(Curve, P)}')
print(f'happy(C, Q) = {happy(Curve, Q)}')

print(f'P = {P}')
print(f'Q = {Q}')

print(f'm1 * P = {year(Curve, P, m1)}')
print(f'm2 * Q = {year(Curve, Q, m2)}')


"""
happy(C, P) = True
happy(C, Q) = True
P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
m1 * P = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
m2 * Q = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933) 
"""
