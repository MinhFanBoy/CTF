from sage.all import *
from flag import flag,n,delta

def hadamard_ratio(basis):
    dimension = basis.nrows()
    det_Lattice = det(basis)
    mult=1.0
    for v in basis:
        mult *= float(v.norm(2))
    hratio = (det_Lattice / mult) ** (1/dimension)
    return hratio

def get_key(n):
    l = 7
    k = ceil(sqrt(n) + 1) * l
    I = identity_matrix(n)
    while 1:
        V_ = random_matrix(ZZ,n, n, x=-l, y=l)
        V = V_ + I*k
        hada_ratio = hadamard_ratio(V)
        if hada_ratio > 0.86:
            U = unimodular_matrix(n)
            W = V * U
            return V, W
        else:
            continue

def unimodular_matrix(n):
    S = identity_matrix(n)
    X = identity_matrix(n)
    for i in range(n):
        for j in range(i,n):
            S[j, i] = choice([-1,1])
            X[i, j] = choice([-1,1])
    assert  det(S*X) == 1 or det(S*X) == -1
    return S*X

def get_error(n,delta):
    k = 4*delta -2
    tmp = []
    tmp += [delta - 2]*(n//k)
    tmp += [delta - 1]*( ((k-2)*n) // (2*k))
    tmp += [delta]*(n//k)
    tmp += [delta + 1]*( ((k-2)*n) // (2*k))
    return tmp

assert len(flag) == 44
assert delta < 20

V,W = get_key(n) 
gift = str(hex(randint(70, 80))).zfill(5).encode('utf-8')
flag =  gift + flag
print(flag)
m = [i for i in flag]
pad = [randint(-128, 127) for i in range(n-len(m)) ]
m = vector(ZZ, m + pad)
r = vector(get_error(n,delta))
c = m * W + r
assert floor((r).norm()) == delta*(floor(sqrt(n)))

with open('pubkey.txt', 'w') as f:
    f.write(str(W)) 

with open('ciphertext.txt', 'w') as f:
    f.write(str(c))
