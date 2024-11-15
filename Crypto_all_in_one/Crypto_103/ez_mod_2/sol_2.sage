
from Crypto.Util.number import *
from random import *

def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%03d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)
def eval_bytes(f):
    return sum([j * (256 ** i) for i, j in enumerate(f[::-1])])

table = "Nss" # 78, 115
# flag = b"NSSCTF{" + "".join([choice(table) for i in range(100)]).encode() + b"}"

p = 421384892562377694077340767015240048728671794320496268132504965422627021346504549648945043590200571
c = 273111533929258227142700975315635731051782710899867431150541189647916512765137757827512121549727178

M = matrix(GF(p), [
    [ord("N"), 1],
    [ord("s"), 1]
])

N = column_matrix(GF(p), [1, 0])

a, b = [int(_[0]) for _ in M.solve_right(N)]

k = bytes_to_long(b"NSSCTF{") * 256^101 + bytes_to_long(b"}")
k = a * (c - k) % p

for i in range(1, 101):
    k += b * pow(256, i, p) 

M = [pow(256, i , p) for i in range(1, 101)]
M = M[::-1] + [k % p]

M = block_matrix([
    [1, column_matrix(M)],
    [0, matrix([[p]])]
])

M[:, -1] *= 2 ** 100
M = M.BKZ(block_sizes = 20)

for i in M:
    if i[-1] == 0 and i[-2] == 1:
        print(i)
        m = ""
        for _ in i[:-2]:
            if _ == 0:
                m += "N"
            else:
                m += "s"
        print("NSSCTF{" + m + "}")
        break