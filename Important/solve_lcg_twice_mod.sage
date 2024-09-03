
"""
1. 
"""


def solve_lcg_twice_mod(out, a, b, p, mod):
    """
    with (out[i] * mod * k[i) = a * (out[i - 1] + mod * k[i-1]) + b (mod p)
    a: mul constant
    b: add constant
    p: mod constant
    mod: mod value
    out: list of output values
    
    """
    n = len(out)
    M = [[0 for _ in range(n+1)] for _ in range(n+1)]
    k = [0]*n
    k[0] = b
    B = []

    for i in range(1,n-1):
        k[i] = (k[i-1] + a^i*b) % p
    A = [ZZ(a^i % p) for i in range(1, n)]

    for i in range(n-1):
        B.append(ZZ((A[i]*out[0] + k[i] - out[i+1]) * ZZ(pow(mod, -1, p)) % p))

    T = matrix(QQ, [
        A,
        B
    ])
    
    M = block_matrix(QQ, [
        [identity_matrix(QQ, n - 1) * p, 0],
        [T, 1]
    ])

    bound = p / mod
    M[-1, -1] = bound
    M[-2, -2] = bound/p

    for row in M.LLL():
        if row[-1] == bound:
            n0 = int((row[0] - B[0]) * pow(A[0], -1, p) % p)
            
            seed = (int(n0 * 100 + out[0]) % p - b) * pow(a, -1, p) % p
            return seed

"""
2.
"""


def solve_lcg_twice_mod(out, a, b, p, mod):
    load('https://gist.githubusercontent.com/Connor-McCartney/952583ecac836f843f50b785c7cb283d/raw/5718ebd8c9b4f9a549746094877a97e7796752eb/solvelinmod.py')
    n = len(out)

    x = [var(f"x{i}") for i in range(n)]
    s = var("s")
    eqs = []

    for mon, c in zip(x, out):
        s = a * s + b
        eqs.append((s == c + mod * mon, p))

    bound = {var("s"): (0, p)}
    for i in x:
        bound[i] = (0, 2 ** (p.nbits() - mod.nbits()))
        
    seed = solve_linear_mod(eqs, bound)[var("s")]
    return seed
