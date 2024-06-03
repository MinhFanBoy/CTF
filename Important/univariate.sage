
from sage.rings.polynomial.multi_polynomial_sequence import PolynomialSequence
import cysignals
import itertools
from re import sub as re_sub



def _from_sagematrix_to_fplllmatrix(mat: matrix) -> str:
    return '[' + re_sub(
        r'\[ ',
        r'[',
        re_sub(r' +', r' ', str(mat))
    ) + ']'


def _fplllmatrix_to_sagematrix(matrixstr: str) -> matrix:
    matlist = eval(matrixstr.replace(' ', ',').replace('\n', ','))
    return matrix(ZZ, matlist)


def _transformation_matrix(mat, lllmat, use_pari_matsol=False):
    # pari.matker() does not assure smallest kernel in Z (seems not call hermite normal form)
    # Sage kernel calls hermite normal form
    #
    # for computing ZZ transformation, use pari.matker, pari.matsolvemod
    # assume first kerdim vectors for lllmat are zero vector
    #
    # anyway, transformation computation after LLL/BKZ is slow.
    # instead, use builtin transformation computation on LLL/BKZ package

    if use_pari_matsol:
        mat_pari = pari.matrix(mat.nrows(), mat.ncols(), mat.list())
        ker_pari_t = pari.matker(pari.mattranspose(mat_pari), 1)
        kerdim = len(ker_pari_t)
        if kerdim == 0:
            # empty matrix
            trans = matrix(ZZ, 0, mat.nrows())
        else:
            trans = matrix(ZZ, pari.mattranspose(ker_pari_t).Col().list())

        mat_pari = pari.matrix(mat.nrows(), mat.ncols(), mat.list())
        for i in range(kerdim, lllmat.nrows(), 1):
            lllmat_pari = pari.vector(lllmat.ncols(), lllmat[i].list())
            trans_pari_t = pari.matsolvemod(
                pari.mattranspose(mat_pari), 0, pari.mattranspose(lllmat_pari)
            )
            transele = matrix(ZZ, trans_pari_t.mattranspose().Col().list())
            trans = trans.stack(transele)
    else:
        trans = mat.kernel().matrix()
        kerdim = trans.nrows()

        for i in range(kerdim, lllmat.nrows(), 1):
            transele = mat.solve_left(lllmat[i])
            trans = trans.stack(transele)

    return trans


def do_LLL_flatter(
        mat: matrix,
        transformation: bool = False,
        use_pari_kernel: bool = False, use_pari_matsol: bool = False
    ):


    if mat == zero_matrix(ZZ, mat.nrows(), mat.ncols()):
        return mat, identity_matrix(ZZ, mat.nrows())

    # sage has integer_kernel(), but somehow slow. instead using pari.matker
    if use_pari_kernel:
        mat_pari = pari.matrix(mat.nrows(), mat.ncols(), mat.list())
        ker_pari_t = pari.matker(mat_pari.mattranspose(), 1)
        ker = matrix(ZZ, ker_pari_t.mattranspose().Col().list())
    else:
        ker = mat.kernel().matrix()

    kerdim = ker.nrows()
    matrow = mat.nrows()
    col = mat.ncols()
    if kerdim == matrow: # full kernel
        return zero_matrix(ZZ, matrow, col), ker
    if kerdim == 0:
        Hsub = mat
        U = identity_matrix(ZZ, matrow)
    else:

        found_choice = False
        ker_submat_rows = tuple(range(kerdim))
        ker_submat_cols = []
        pivot = matrow - 1
        # search submatrix of kernel assuming last column vectors are triangulate
        while len(ker_submat_cols) < kerdim:
            if ker[ker_submat_rows, tuple([pivot])] != zero_matrix(ZZ, kerdim, 1):
                ker_submat_cols.append(pivot)
            pivot -= 1
        ker_submat_cols = tuple(sorted(ker_submat_cols))
        ker_last_det = int(ker[ker_submat_rows, ker_submat_cols].determinant())
        if ker_last_det == 0:
            raise ValueError("no unimodular matrix found (cause ker_last_det=0)")
        for choice in range(pivot, -1, -1):
            # gcd check
            gcd_row = ker_last_det
            for i in range(kerdim):
                gcd_row = GCD(gcd_row, ker[i, choice])
            if abs(gcd_row) != 1:
                continue

            # choice pivot: last columes for kernel are triangulated and small
            kersubidxes = [choice] + list(ker_submat_cols)
            detlst = [ker_last_det]
            for i in range(1, kerdim+1, 1):
                ker_submat_rows = tuple(range(kerdim))
                ker_submat_cols = tuple(kersubidxes[:i] + kersubidxes[i+1:])
                detlst.append(ker[ker_submat_rows, ker_submat_cols].determinant())
                detlist_gcd, detlist_coef = _xgcd_list(detlst)
                if detlist_gcd == 1:
                    found_choice = True
                    break
            if not found_choice:
                continue
            detlist_coef = detlist_coef + [0] * ((kerdim + 1) - len(detlist_coef))
            break
        if not found_choice:
            raise ValueError("no unimodular matrix found")
        U_top_vec = [0 for _ in range(matrow)]
        for i in range(kerdim+1):
            U_top_vec[kersubidxes[i]] = (-1)**i * detlist_coef[i]
        U_sub = matrix(ZZ, 1, matrow, U_top_vec)
        not_kersubidxes = sorted(list(set(list(range(matrow))) - set(kersubidxes)))
        for j in range(kerdim+1, matrow):
            onevec = [0 for _ in range(matrow)]
            onevec[not_kersubidxes[j-(kerdim+1)]] = 1
            U_sub = U_sub.stack(vector(ZZ, matrow, onevec))
        Hsub = U_sub * mat
        U = ker.stack(U_sub)
        #assert abs(U.determinant()) == 1

    if Hsub.nrows() == 1:
        lllmat = Hsub
    else:
        matstr = _from_sagematrix_to_fplllmatrix(Hsub)
        result = subprocess_run(
            'flatter',
            input=matstr.encode(), capture_output=True
        )
        if result.returncode != 0:
            print(result.stderr)
            raise ValueError(f"LLL failed with return code {result.returncode}")
        lllmat = _fplllmatrix_to_sagematrix(result.stdout.decode().strip())

    if transformation:
        trans = _transformation_matrix(Hsub, lllmat, use_pari_matsol=use_pari_matsol)
    else:
        trans = None

    restrows = mat.nrows() - lllmat.nrows()
    final_lllmat = zero_matrix(ZZ, restrows, lllmat.ncols()).stack(lllmat)

    if transformation:
        middle_trans = identity_matrix(ZZ, restrows).augment(zero_matrix(ZZ, restrows, trans.ncols())).stack(
            zero_matrix(ZZ, trans.nrows(), restrows).augment(trans)
        )
        final_trans = middle_trans * U
        #assert abs(final_trans.determinant()) == 1
        #assert final_trans * mat == final_lllmat
    else:
        final_trans = None

    return final_lllmat, final_trans

def generate_polynomial(N, _p):
    coefficients = []
    bounds = []
    i = 0
    ii = 0
    is_previous_unknown = True if _p[-1] == '?' else False

    for char in _p[::-1]:
        is_current_unknown = True if char == '?' else False
        if is_current_unknown and not is_previous_unknown:
            coefficients.append(2^(4*ii))
            i = 0
        if not is_current_unknown and is_previous_unknown:
            bounds.append(2^(4*i))
        is_previous_unknown = is_current_unknown
        i += 1
        ii += 1

    if is_current_unknown:
        bounds.append(2^(4*i))

    if _p[-1] == '?':
        coefficients = coefficients[::-1]
        coefficients.append(1)

    d = len(coefficients)
    xs = [f"x{i}" for i in range(d)]
    PR = PolynomialRing(Zmod(N), d, xs)
    f = int(_p.replace("?", "0"), 16) + sum([c * PR.objgens()[1][n] for n, c in enumerate(coefficients)])
    return f, bounds[::-1]

def univariate(f, X, beta=1.0, m=None):
    N = f.parent().characteristic()
    delta = f.degree()
    if m is None:
        epsilon = RR(beta^2/f.degree() - log(2*X, N))
        m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
    t = int((delta*m*(1/beta - 1)).floor())
    #print(f"m = {m}")
    
    f = f.monic().change_ring(ZZ)
    P,(x,) = f.parent().objgens()
    g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta)]
    g.extend([x**i * f**m for i in range(t)]) 
    B = Matrix(ZZ, len(g), delta*m + max(delta,t))

    for i in range(B.nrows()):
        for j in range(g[i].degree()+1):
            B[i,j] = g[i][j]*X**j

    try:
        B, _ = do_LLL_flatter(B)
    except:
        B = B.LLL()
    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <= X])
    return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]
