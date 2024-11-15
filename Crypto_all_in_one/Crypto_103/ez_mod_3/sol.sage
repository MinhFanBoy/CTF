from Crypto.Util.number import *
from random import *

p = 382341578876755047910270786090569535013570954958220282576527310027607029356817834229805565170363061
table1 = "NsS"
table2 = [363240026866636825072669542082311717933742315917012606686823760007829170314055842025699242629919061, 353526073204447024446020739384656942280539226749705781536551943704760671350652481846175115676519925, 343812119542257223819371936687002166627336137582398956386280127401692172387249121666650988723120789]
choose = [choice(table1) for i in range(100)]

flag = b"NSSCTF{" + "".join(choose).encode() + b"}"
c = 0

for i in range(len(choose)):
    c += 256**i*table2[table1.index(choose[i])]
    c %= p

c = 207022199908418203957326448601855685285890830964132201922954241454827344173832839490247666897642796

"""

[c0, 1, 1]
[c1, 1, 1]
[c2, 1, 1]

[-1, 0, 1]
"""

A = matrix(GF(p), [
    [table2[0], 1],
    [table2[1], 1],
    [table2[2], 1]
])

B = column_matrix(GF(p), [1, 0, -1])

a, b = [int(_[0]) for _ in A.solve_right(B)]

c = a * c % p

for i in range(100):
    c += b * (pow(256, i, p))
    
M = column_matrix([pow(256, i, p) for i in range(100)] + [-c % p])

M = block_matrix([
    [1, M],
    [0, matrix([[p]])]
])

M[:, -1] *=  2 ** 100

M = M.BKZ(block_sizes = 20)

for i in M:
    if i[-1] == 0 and i[-2] == 1:
        print(i)
        m = ""
        
        for _ in i[:-2]:
            if _ == 1:
                m += table1[0]
            elif _ == 0:
                m += table1[1]
            elif _ == -1:
                m += table1[2]
                
        print("NSSCTF{" + m + "}")
        break