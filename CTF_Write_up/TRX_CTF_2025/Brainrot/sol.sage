
from Crypto.Util.number import *
import s

out = [25655763503777127809574173484, 8225698895190455994566939853, 10138657858525287519660632490]
points = [0xdeadbeef, 13371337, 0xcafebabe]
coeffs = [var(f"c{i}") for i in range(0, 40, 4)]

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

F = PolynomialRing(ZZ, 'f', 43)
flags = F.gens()[:40]
flag = [f + 76 for f in flags]
k = F.gens()[-3:]

def rot_encode(s):
    return sum([((s[j] + 0x40)*256 + 0x1f)*(256**2)**(3-j) for j in range(4)])+ 0xfffe0000000000000000
coeffs = [rot_encode(flag[i: i + 4]) for i in range(0, len(flag), 4)]
def poly(x):
    return sum([c*x**i for i,c in enumerate(coeffs)])

f = []
for i, p in enumerate(points):
    f.append(poly(p) - out[i] - (k[i]) * bytes_to_long(b'only_half!!!'))

def coefficients(f):
    tmp = []
    for i in F.gens():
        tmp.append(f.coefficient(i))
    return tmp + [f.constant_coefficient()]

M = matrix([coefficients(i) for i in f]).T
M = block_matrix(ZZ, [
    [M, 1],
    [bytes_to_long(b'cant_give_you_everything'),0]
    ])

w = diagonal_matrix([1]*3 + [44]*40+ [(bytes_to_long(b'cant_give_you_everything')//bytes_to_long(b'only_half!!!')) >> 1]*3 + [1], sparse=False)
M /= w
M = M.BKZ(block_size=40, proof=False)
M *= w

for row in M:
    if row[-1] == 1 or row[-1] == -1:
        try:
            print(bytes(x+76 for x in (row[3:43])).decode())
        except:
            pass
        try:
            print(bytes(x+76 for x in (-row[3:43])).decode())
        except:
            pass
        # CurS37_aG4i##n_1nDiAneS#s_T0_7h3_Mo0n!!!
