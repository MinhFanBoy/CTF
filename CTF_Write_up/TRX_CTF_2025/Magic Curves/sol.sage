

from Crypto.Util.number import *
# from sage.schemes.elliptic_curves.constructor import coefficients_from_j
from tqdm import *
import multiprocessing as mp
def find_curve(a):
    while True:
        p = getPrime(216)
        if (p - 1) % 5 == 0:
            break
    G = GF(p)
    lam = G(1).nth_root(5)
    for i in trange(1000):
        a = G.random_element()
        b = a * pow(lam, -3, p)
        e = EllipticCurve(G, [a, b])
        if all(x < 2**60 for x, _ in e.order().factor()):
            print(p, a, b)

with mp.Pool(22) as p:
    p.map(find_curve, range(1000))