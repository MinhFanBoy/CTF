from tqdm import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime
from random import getrandbits
from Crypto.Util.number import *

def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)

f = open("output", "r").readlines()

for i in f:
    exec(i.strip())

p = p
M = M
Ma = Ma
Mb = Mb
ct = ct

G = Zmod(p ** 3)
PR.<x> = PolynomialRing(G)
M = matrix(G, M)
Ma = matrix(G, Ma)
Mb = matrix(G, Mb)

g = M.charpoly()
a = Ma.charpoly()
b = Mb.charpoly()

def binomial_dlog_sub(y,g,p,q,r=2):
    C = ZZ(pow(y, q, p^r))
    B = ZZ(pow(g, q, p^r))
    kx = (C - 1)//p^(r-1)
    k =  (B - 1)//p^(r-1)
    x = ZZ(kx * pow(k, -1, p) % p)
    return x

def binomial_dlog(y,g,p,q,r):
    # solve y = g^x \mod p^r where q=phi(p) such that g^q = 1 \mod p
    assert r >= 2
    y = ZZ(y)
    g = ZZ(g)
    xs = []
    for i in range(r-1):
        xi = binomial_dlog_sub(y, g, p, q, i + 2)
        xs.append(xi)
        y = ZZ(y * pow(g,-xi,p^r) % p^r)
        g = ZZ(pow(g,p,p^r))
    return ZZ(xs, p)

def hensel_lift(f, p, k, i=0):
    """
    f: đa thức cần tìm nghiệm
    p: số nguyên tố
    k: số mũ của p muốn nâng lên (p^k)
    i: nghiệm thứ i của f mod p
    """
    fp = f.change_ring(Zmod(p))
    g0 = int(fp.roots()[i][0])
    
    result = g0
    power = 1
    
    for i in range(1, k):
        
        curr_poly = (f(result + x * p**power).change_ring(ZZ) / (p**power)).change_ring(Zmod(p))
        ti = int(curr_poly.roots()[0][0])
        result = result + ti * (p**power)
        power += 1
        
    return int(result)



def d_log(k, base, p, r): 

    # solve k = base ^ x (mod p^r)
    
    def d_log_sub(k, base, p, r):

    # sol that: base ^ x = k (mod p ^ r) => find x

        q = p - 1
        c = (ZZ(pow(k, q, p ^ r)) - 1) // (p ^ (r - 1))
        d = (ZZ(pow(base, q, p ^ r)) - 1) // (p ^ (r - 1))
        x = ZZ((pow(d, -1, p) * c) % p)

        return x
    
    k = ZZ(k)
    base = ZZ(base)
    xs = []

    for i in range(r-1):
        xi = d_log_sub(k, base, p, i + 2)
        xs.append(xi)
        k = ZZ(k * pow(base,-xi,p^r) % p^r)
        base = ZZ(pow(base,p,p^r))
    return ZZ(xs, p)

def d_log(k, base, p, r): 

    # solve k = base ^ x (mod p ^ r)
    R = Zp(p, prec = r)
    return (R(k).log() / R(base).log()).lift()

g1 = hensel_lift(g, p, 1, i = 1)
a1 = hensel_lift(a, p, 1, i = 1)

T = 99986015309131554073222673357191122700463502810799771
order = 11 * 1399 * 576647 * 707717 * 31455197

a_1 = discrete_log(Mod(pow(a1,T,p),p),Mod(pow(g1,T,p),p),ord=order)

g2 = hensel_lift(g, p, 2, i = 1)
a2 = hensel_lift(a, p, 2, i = 1)

a_2 = binomial_dlog(a2, g2, p, (p - 1), 2)

g3 = hensel_lift(g, p, 3, i = 1)
a3 = hensel_lift(a, p, 3, i = 1)

a_3 = binomial_dlog(a3, g3, p, (p - 1), 3)
# print(xa)
# print((pow(g3, xa, p ** 3) - a3) % (p ** 3))

a_ = crt([a_2, a_1], [p * (p - 1), order])
print(a_)
a =  3252424492932335710113083947875131225240197576701027092531662276031618802648263217323062670742686213740942922979212534962194866012538868201949253298148367181530386764587695735363
print(a - int(a_))

mod = (p) * order
while M ** a_ != Ma:
    a_ += mod
    print(a - int(a_))
S = Mb ** a_
key = sha256(S.str().encode()).digest()
print(AES.new(key, AES.MODE_ECB).decrypt(long_to_bytes(ct)))