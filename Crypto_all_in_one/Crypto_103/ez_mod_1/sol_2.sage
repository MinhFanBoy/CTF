
from Crypto.Util.number import *
from tqdm import *

def eval_bytes(f):
    return sum([j * (256 ** i) for i, j in enumerate(f[::-1])])

p = 324556397741108806830285502585098109678766437252172614832253074632331911859471735318636292671562523
c = 141624663734155235543198856069652171779130720945875442624943917912062658275440028763836569215230250

F = PolynomialRing(Zmod(p), [f"x_{i}" for i in range(80)])
x = F.gens()

f = [i for i in b"NSSCTF{"] + [_ + 51 for _ in x] + [ord("}")]
n = 80
f = eval_bytes(f) - c

M = [int(_ %  p) for _ in f.coefficients()[:-1]][::-1] + [int(f.coefficients()[-1])]

M = block_matrix([
    [1, column_matrix(M)],
    [0, matrix([[p]])]
])

M[:, -1] *= 2 ** 100

for line in M.BKZ(block_size=20):
    m = ""
    if line[-1] == 0 and abs(line[-2]) == 1:
        for i in line[:-2]:
            m += chr((51 + i))
        flag = "NSSCTF{" + m[::-1] + "}"
        print(flag)
        break