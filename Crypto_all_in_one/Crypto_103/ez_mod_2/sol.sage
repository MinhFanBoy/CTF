from Crypto.Util.number import *
from random import *

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

F = PolynomialRing(Zmod(p), [f"x_{i}" for i in range(100)])
x = F.gens()

f = [i for i in b"NSSCTF{"] + [_ for _ in x] + [ord("}")]

f_ = [int(b) for _ in x] + [0]

f = eval_bytes(f) - a * c - eval_bytes(f_)

M = [int(_ %  p) for _ in f.coefficients()[:-1]][::-1] + [int(f.coefficients()[-1] % p)]

M = block_matrix([
    [1, column_matrix(M)],
    [0, matrix([[p]])]
])

M[:, -1] *= 2 ** 120

for line in M.BKZ(block_size=20):
    m = ""
    if line[-1] == 0 and abs(line[-2]) == 1:
        for i in line[:-2]:
            if i == 0:
                m += "N"
            else:
                m += "s"
        print(m[::-1]) 