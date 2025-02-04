

# This file was *autogenerated* from the file sol_2.sage
from sage.all_cmdline import *   # import sage library

_sage_const_0 = Integer(0); _sage_const_1 = Integer(1); _sage_const_60 = Integer(60); _sage_const_256 = Integer(256); _sage_const_421384892562377694077340767015240048728671794320496268132504965422627021346504549648945043590200571 = Integer(421384892562377694077340767015240048728671794320496268132504965422627021346504549648945043590200571); _sage_const_273111533929258227142700975315635731051782710899867431150541189647916512765137757827512121549727178 = Integer(273111533929258227142700975315635731051782710899867431150541189647916512765137757827512121549727178); _sage_const_101 = Integer(101); _sage_const_2 = Integer(2); _sage_const_100 = Integer(100); _sage_const_20 = Integer(20)
from Crypto.Util.number import *
from random import *

def matrix_overview(BB):
    for ii in range(BB.dimensions()[_sage_const_0 ]):
        a = ('%03d ' % ii)
        for jj in range(BB.dimensions()[_sage_const_1 ]):
            if BB[ii, jj] == _sage_const_0 :
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[_sage_const_0 ] < _sage_const_60 :
                a += ' '
        print(a)
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

k = bytes_to_long(b"NSSCTF{") * _sage_const_256 **_sage_const_101  + bytes_to_long(b"}")
k = a * (c - k) % p

for i in range(_sage_const_1 , _sage_const_101 ):
    k += b * pow(_sage_const_256 , i, p) 

M = [pow(_sage_const_256 , i , p) for i in range(_sage_const_1 , _sage_const_101 )]
M = M[::-_sage_const_1 ] + [k % p]

M = block_matrix([
    [_sage_const_1 , column_matrix(M)],
    [_sage_const_0 , matrix([[p]])]
])

M[:, -_sage_const_1 ] *= _sage_const_2  ** _sage_const_100 
M = M.BKZ(block_sizes = _sage_const_20 )

for i in M:
    if i[-_sage_const_1 ] == _sage_const_0  and i[-_sage_const_2 ] == _sage_const_1 :
        print(i)
        m = ""
        for _ in i[:-_sage_const_2 ]:
            if _ == _sage_const_0 :
                m += "N"
            else:
                m += "s"
        print("NSSCTF{" + m + "}")
        break

