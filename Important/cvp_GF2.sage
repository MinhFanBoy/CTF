
from sage.all import *
from sage.coding.linear_code import LinearCode
from sage.coding.information_set_decoder import LeeBrickellISDAlgorithm

def cvp_GF2(M, target, threshold=0.05):
    n, k = M.dimensions()
    C = LinearCode(M)
    D = LeeBrickellISDAlgorithm(C, decoding_interval=((n / 2) * threshold, (n * 3 / 2) * threshold))
    

    sol = D.decode(target)
    return (M.solve_left(sol), sol)
