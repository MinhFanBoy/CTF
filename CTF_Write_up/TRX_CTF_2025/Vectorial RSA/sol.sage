from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, getRandomInteger
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import numpy as np
import secrets
import hashlib
import random
import os
import logging
from Crypto.Util.number import *
from tqdm import *
from sage.all import ZZ
from sage.all import Zmod

def _polynomial_hgcd(ring, a0, a1):
    assert a1.degree() < a0.degree()

    if a1.degree() <= a0.degree() / 2:
        return 1, 0, 0, 1

    m = a0.degree() // 2
    b0 = ring(a0.list()[m:])
    b1 = ring(a1.list()[m:])
    R00, R01, R10, R11 = _polynomial_hgcd(ring, b0, b1)
    d = R00 * a0 + R01 * a1
    e = R10 * a0 + R11 * a1
    if e.degree() < m:
        return R00, R01, R10, R11

    q, f = d.quo_rem(e)
    g0 = ring(e.list()[m // 2:])
    g1 = ring(f.list()[m // 2:])
    S00, S01, S10, S11 = _polynomial_hgcd(ring, g0, g1)
    return S01 * R00 + (S00 - q * S01) * R10, S01 * R01 + (S00 - q * S01) * R11, S11 * R00 + (S10 - q * S11) * R10, S11 * R01 + (S10 - q * S11) * R11


def fast_polynomial_gcd(a0, a1):
    """
    Uses a divide-and-conquer algorithm (HGCD) to compute the polynomial gcd.
    More information: Aho A. et al., "The Design and Analysis of Computer Algorithms" (Section 8.9)
    :param a0: the first polynomial
    :param a1: the second polynomial
    :return: the polynomial gcd
    """
    # TODO: implement extended variant of half GCD?
    assert a0.parent() == a1.parent()

    if a0.degree() == a1.degree():
        if a1 == 0:
            return a0
        a0, a1 = a1, a0 % a1
    elif a0.degree() < a1.degree():
        a0, a1 = a1, a0

    assert a0.degree() > a1.degree()
    ring = a0.parent()

    # Optimize recursive tail call.
    while True:
        logging.debug(f"deg(a0) = {a0.degree()}, deg(a1) = {a1.degree()}")
        _, r = a0.quo_rem(a1)
        if r == 0:
            return a1.monic()

        R00, R01, R10, R11 = _polynomial_hgcd(ring, a0, a1)
        b0 = R00 * a0 + R01 * a1
        b1 = R10 * a0 + R11 * a1
        if b1 == 0:
            return b0.monic()

        _, r = b0.quo_rem(b1)
        if r == 0:
            return b1.monic()

        a0 = b1
        a1 = r

e1 = [2, 3, 5, 7]
a1 = [69, 420, 1337, 9001]
e2 = [11, 13, 17, 19]
a2 = [72, 95, 237, 1001]

n = 64541532379927077000559872397264097749021972434205531336066931690486076647705413170185144940288988381635799051758671701941067093853968684354158364531117205968958931132385165913434941347527993061497902723498417954305499807823689010185704770834752024422286910181187814374841629893530443736915542004920807142781
eA = 27
eB = 35
cA = 44022142978819419618353382999440345073976186907275599632322745080012623162430540188907724797065065001963223657911160722898910372812863352246726924386760519377252296888984296509586878063185483891399718374344520697641288446229397649573154526152818589294889851730684140323675940582528405188097712041985150863134
cB = 36492103245285092647843551854942925373394229095706870054555977026553850101701906739652840770223455473246919620658344617649832752419944319254556813129428929352359138539967235739316345067424590082471814489355137379436050816028192665505036173068173821426333394966323037686047535779525861943853094214085274696593

iv = bytes.fromhex("922d9991e13113013496ada61eb3103c")
ciphertext = bytes.fromhex("5d2a59c1b5a5268baea17b095ad62310a0442eeeb2a6497f4074d70628f4ec5d51008a4ff12a6ea722e171656386f698ae530ac0824b0f5a77a93e2c063ac2f1")

F.<x> = PolynomialRing(Zmod(n))

# The public strengths of Generals Alicius and Bobius
eA = 27  # Alicius' power
eB = 35  # Bobius' power

c1_ = sum([a * x ** e for a, e in zip(a1, e1)])
for b in trange(54800 + 20, 54800 + 30):
    c2_ = sum([a * (x - b) ** e for a, e in zip(a2, e2)])
    k = (fast_polynomial_gcd(c1_ ** eB - cA, c2_ ** eA - cB))
    if k != 1:

        kA = int(-k.monic().constant_coefficient() % n)

        c1 = sum([a * pow(kA, e, n) for a, e in zip(a1, e1)])  
        c2 = sum([a * pow(kB, e, n) for a, e in zip(a2, e2)]) 
        cA = pow(c1, eB, n) 
        cB = pow(c2, eA, n)  

        key = long_to_bytes(c1 + c2)
        key = hashlib.sha256(key).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        flag = cipher.decrypt(ciphertext)  
        print(flag)
