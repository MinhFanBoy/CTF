
from Crypto.Util.number import *
from tqdm import *
import os
from re import findall
from subprocess import check_output

def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))


def small_roots(self, X=None, beta=1.0, epsilon=None, **kwds):
    from sage.misc.verbose import verbose
    from sage.matrix.constructor import Matrix
    from sage.rings.real_mpfr import RR

    N = self.parent().characteristic()

    if not self.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    beta = RR(beta)
    if beta <= 0.0 or beta > 1.0:
        raise ValueError("0.0 < beta <= 1.0 not satisfied.")

    f = self.change_ring(ZZ)

    P, (x,) = f.parent().objgens()

    delta = f.degree()

    if epsilon is None:
        epsilon = beta / 8
    verbose("epsilon = %f" % epsilon, level=2)

    m = max(beta**2 / (delta * epsilon), 7 * beta / delta).ceil()
    verbose("m = %d" % m, level=2)

    t = int((delta * m * (1 / beta - 1)).floor())
    verbose("t = %d" % t, level=2)

    if X is None:
        X = (0.5 * N ** (beta**2 / delta - epsilon)).ceil()
    verbose("X = %s" % X, level=2)

    # we could do this much faster, but this is a cheap step
    # compared to LLL
    g = [x**j * N ** (m - i) * f**i for i in range(m) for j in range(delta)]
    g.extend([x**i * f**m for i in range(t)])  # h

    B = Matrix(ZZ, len(g), delta * m + max(delta, t))
    for i in range(B.nrows()):
        for j in range(g[i].degree() + 1):
            B[i, j] = g[i][j] * X**j

    B = flatter(B)

    f = sum([ZZ(B[0, i] // X**i) * x**i for i in range(B.ncols())])
    R = f.roots()

    ZmodN = self.base_ring()
    roots = set([ZmodN(r) for r, m in R if abs(r) <= X])
    Nbeta = N**beta
    return [root for root in roots if N.gcd(ZZ(self(root))) >= Nbeta]

def Decimal_conversion(num):
    if num == 0:
        return '0'
    digits = []
    while num:
        digits.append(str(num % 5))
        num //= 5
    return ''.join(reversed(digits))


leak = "2011133132443111302000224204142244403203442000141102312242343143241244243020003333022112141220422134444214010012"
n = 85988668134257353631742597258304937106964673395852009846703777410474172989069717247424903079500594820235304351355706519069516847244761609583338251489134035212061654870087550317540291994559481862615812258493738064606592165529948648774081655902831715928483206013332330998262897765489820121129058926463847702821
e = 65537
c = 64708526479058278743788046708923650158905888858865427385501446781738669889375403360886995849554813207230509920789341593771929287415439407977283018525484281064769128358863513387658744063469874845446480637925790150835186431234289848506337341595817156444941964510251032210939739594241869190746437858135599624562

F.<x> = PolynomialRing(Zmod(n))
l = 221

for i in trange(5 ** 2, 5 ** 3):
    leak_ = str(leak) + str(Decimal_conversion(i))
    k = (l - len(leak_))
    leak_ = leak_ + "0" * k

    leak_ = int(leak_, 5)
    f = leak_ + x

    roots = small_roots(f, X = 5 ** k, beta=0.4, epsilon=0.01)
    # p = leak_ + 32101510087127687659084157115424406004147638592035304998344600931673409328

    # q = n // p
    # print(long_to_bytes(int(pow(c, inverse(e, (p - 1) * (q - 1)), n))))
