
"""

source code from: + https://yanmo312.github.io/2022/11/26/gemima_6/#%EF%BC%88%E4%BA%8C%EF%BC%89%E8%A7%A3%E5%86%B3%E6%96%B9%E6%B3%95-1

other documents:
+ https://blog.maple3142.net/2022/01/19/ais3-eof-ctf-quals-2021-writeups/#notprng
+ https://hackmd.io/@theoldmoon0602/B1klrLDzq
+ https://gist.github.com/grocid/62081c82c077eae83f61a9c03b405c84

script solution for `Karen - zer0pts CTF 2022` 

"""

def allpmones(v):
    return len([vj for vj in v if vj in [-1, 0, 1]]) == len(v)

# We generate the lattice of vectors orthogonal to b modulo x0
def orthoLattice(b, x0):
    m = b.length()
    M = Matrix(ZZ, m, m)

    for i in range(1, m):
        M[i, i] = 1
    M[1:m, 0] = -b[1:m] * inverse_mod(b[0], x0)
    M[0, 0] = x0

    for i in range(1, m):
        M[i, 0] = mod(M[i, 0], x0)

    return M

def allones(v):
    if len([vj for vj in v if vj in [0, 1]]) == len(v):
        return v
    if len([vj for vj in v if vj in [0, -1]]) == len(v):
        return -v
    return None

def recoverBinary(M5):
    lv = [allones(vi) for vi in M5 if allones(vi)]
    n = M5.nrows()
    for v in lv:
        for i in range(n):
            nv = allones(M5[i] - v)
            if nv and nv not in lv:
                lv.append(nv)
            nv = allones(M5[i] + v)
            if nv and nv not in lv:
                lv.append(nv)
    return Matrix(lv)

def kernelLLL(M):
    n = M.nrows()
    m = M.ncols()
    if m < 2 * n:
        return M.right_kernel().matrix()
    K = 2 ^ (m // 2) * M.height()

    MB = Matrix(ZZ, m + n, m)
    MB[:n] = K * M
    MB[n:] = identity_matrix(m)

    MB2 = MB.T.LLL().T

    assert MB2[:n, : m - n] == 0
    Ke = MB2[n:, : m - n].T

    return Ke

def attack(m, n, p, h):
    # This is the Nguyen-Stern attack, based on BKZ in the second step
    print("n =", n, "m =", m)

    iota = 0.035
    nx0 = int(2 * iota * n ^ 2 + n * log(n, 2))
    print("nx0 =", nx0)

    x0 = p
    b = vector(h)

    # only information we get
    M = orthoLattice(b, x0)

    t = cputime()
    M2 = M.LLL()
    print("LLL step1: %.1f" % cputime(t))

    # assert sum([vi == 0 and 1 or 0 for vi in M2 * X]) == m - n
    MOrtho = M2[: m - n]

    print("  log(Height, 2) = ", int(log(MOrtho.height(), 2)))

    t2 = cputime()
    ke = kernelLLL(MOrtho)

    print("  Kernel: %.1f" % cputime(t2))
    print("  Total step1: %.1f" % cputime(t))

    if n > 170:
        return

    beta = 2
    tbk = cputime()
    while beta < n:
        if beta == 2:
            M5 = ke.LLL()
        else:
            M5 = M5.BKZ(block_size=beta)

        # we break when we only get vectors with {-1,0,1} components
        if len([True for v in M5 if allpmones(v)]) == n:
            break

        if beta == 2:
            beta = 10
        else:
            beta += 10

    print("BKZ beta=%d: %.1f" % (beta, cputime(tbk)))
    t2 = cputime()
    MB = recoverBinary(M5)
    print("  Recovery: %.1f" % cputime(t2))

    return MB
