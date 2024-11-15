
from collections.abc import Sequence
import math
import operator
from typing import List, Tuple
from sage.all import ZZ, gcd, matrix, prod, var
from Crypto.Util.number import *
from tqdm import *

def eval_bytes(f):
    return sum([j * 256 ^ i for i, j in enumerate(f[::-1])])

load('https://raw.githubusercontent.com/TheBlupper/linineq/main/linineq.py')

p = 324556397741108806830285502585098109678766437252172614832253074632331911859471735318636292671562523
c = 141624663734155235543198856069652171779130720945875442624943917912062658275440028763836569215230250

table = [i for i in b"01234567"]

F = PolynomialRing(Zmod(p), [f"x_{i}" for i in range(80)])
x = F.gens()
f = [i for i in b"NSSCTF{"] + [_ for _ in x] + [ord("}")]
n = 80
f = eval_bytes(f) - c

M = [int(_ %  p) for _ in f.coefficients()[:-1]]
N = int(-f.coefficients()[-1] % p)

M = matrix(M)
lb = [min(table)]*n
ub = [max(table)]*n
print(solve_bounded_mod(M, [N], lb, ub, p))
for cc in solve_bounded_mod_gen(M, [N], lb, ub, p):
    print(cc)