def solve_truncated_lcg(h, a, b, m, trunc):

    """

    solve seed := a * seed + b mod m
    h = [seed << trunc, seed << trunc, ...]
    h: list of int which is LCG's output
    a: mul constant
    b: add constant
    m: modulus constant 
    trunc: unknown bit of output
    
    """


    nbits = 128
    for i in range(len(h)):
        h[i] <<= (nbits - trunc)
        
    A = [1]
    B = [0]

    for i in range(1, len(h)-1):
        A.append(a*A[i-1] % m)
        B.append((a*B[i-1]+a*h[i]+b-h[i+1]) % m)

    A = A[1:]
    B = B[1:]

    C = matrix(QQ, [A, B])

    M = block_matrix(QQ,[
        [identity_matrix(QQ, len(h) - 2) * m, 0],
        [C, 1]
    ])

    M[-1, -1] = 2 ** (nbits - trunc)
    vl = M.LLL()[0]
    l1 = vl[-2]
    h1 = h[1]
    s1 = l1+h1
    seed = ((s1 - b)*inverse_mod(a,m))%m
    seed = ((seed - b)*inverse_mod(a,m))%m
    return seed
