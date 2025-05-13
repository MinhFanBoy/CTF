from out import p, output
from tqdm import *

proof.arithmetic(False)  # Tắt chứng minh để tăng tốc
RR = PolynomialRing(GF(p), [f"a{i}" for i in range(16)] + [f"b{i}" for i in range(16)])
sss = list(RR.gens())
aa = sss[:16]
bb = sss[16:]
a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15 = aa
b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 = bb

def parse_polynomial_with_substitution(text):

    terms = text
    for i, j in enumerate(F.gens()):
        terms = terms.replace(str(j ^ 1337), str(aa[i]))
        terms = terms.replace(str(j ^ 1663), str(bb[i]))
        terms = terms.replace(str(j ^ 3000), str(aa[i] * bb[i]))

    return eval(terms)

F = PolynomialRing(GF(p), 's', 16)
setup = F.gens()

eq = []

for _ in trange(256):

    o = output[6 * (_): 6 * (_ + 1)]
    noise1 = o[0]
    noise2 = o[1]
    noise3 = o[2]
    noise4 = o[3]
    noise5 = o[4]
    s_ = o[5]
    s = -s_
    for i in range(1000):
        s += (noise5[i] * (noise1[i] + pow(setup[noise2[i]], 1337) * pow(setup[noise3[i]], 1663)) + noise4[i])
    __ = (parse_polynomial_with_substitution(str(s)))

    eq.append(__)

I = ideal(eq)
for i in (I.groebner_basis()):
    print(i)
