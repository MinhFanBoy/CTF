

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_256 = Integer(256); _sage_const_1 = Integer(1); _sage_const_421384892562377694077340767015240048728671794320496268132504965422627021346504549648945043590200571 = Integer(421384892562377694077340767015240048728671794320496268132504965422627021346504549648945043590200571); _sage_const_273111533929258227142700975315635731051782710899867431150541189647916512765137757827512121549727178 = Integer(273111533929258227142700975315635731051782710899867431150541189647916512765137757827512121549727178); _sage_const_0 = Integer(0); _sage_const_100 = Integer(100); _sage_const_2 = Integer(2); _sage_const_120 = Integer(120); _sage_const_20 = Integer(20)
from Crypto.Util.number import *
from random import *

def eval_bytes(f):
    return sum([j * (_sage_const_256  ** i) for i, j in enumerate(f[::-_sage_const_1 ])])

table = "Nss" # 78, 115
# flag = b"NSSCTF{" + "".join([choice(table) for i in range(100)]).encode() + b"}"

p = _sage_const_421384892562377694077340767015240048728671794320496268132504965422627021346504549648945043590200571 
c = _sage_const_273111533929258227142700975315635731051782710899867431150541189647916512765137757827512121549727178 

M = matrix(GF(p), [
    [ord("N"), _sage_const_1 ],
    [ord("s"), _sage_const_1 ]
])

N = column_matrix(GF(p), [_sage_const_1 , _sage_const_0 ])

a, b = [int(_[_sage_const_0 ]) for _ in M.solve_right(N)]

F = PolynomialRing(Zmod(p), [f"x_{i}" for i in range(_sage_const_100 )])
x = F.gens()

f = [i for i in b"NSSCTF{"] + [_ for _ in x] + [ord("}")]

f_ = [int(b) for _ in x] + [_sage_const_0 ]

f = eval_bytes(f) - a * c - eval_bytes(f_)

M = [int(_ %  p) for _ in f.coefficients()[:-_sage_const_1 ]][::-_sage_const_1 ] + [int(f.coefficients()[-_sage_const_1 ] % p)]

M = block_matrix([
    [_sage_const_1 , column_matrix(M)],
    [_sage_const_0 , matrix([[p]])]
])

M[:, -_sage_const_1 ] *= _sage_const_2  ** _sage_const_120 

for line in M.BKZ(block_size=_sage_const_20 ):
    m = ""
    if line[-_sage_const_1 ] == _sage_const_0  and abs(line[-_sage_const_2 ]) == _sage_const_1 :
        for i in line[:-_sage_const_2 ]:
            if i == _sage_const_0 :
                m += "N"
            else:
                m += "s"
        print(m[::-_sage_const_1 ]) 

