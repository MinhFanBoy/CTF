from Crypto.Util.number import *
from random import *
import string

import itertools

from collections.abc import Sequence
import math
import operator
from typing import List, Tuple
from sage.all import ZZ, gcd, matrix, prod, var


def _process_linear_equations(equations, vars, guesses) -> List[Tuple[List[int], int, int]]:
    result = []

    for rel, m in equations:
        op = rel.operator()
        if op is not operator.eq:
            raise TypeError(f"relation {rel}: not an equality relation")

        expr = (rel - rel.rhs()).lhs().expand()
        for var in expr.variables():
            if var not in vars:
                raise ValueError(f"relation {rel}: variable {var} is not bounded")

        # Fill in eqns block of B
        coeffs = []
        for var in vars:
            if expr.degree(var) >= 2:
                raise ValueError(f"relation {rel}: equation is not linear in {var}")
            coeff = expr.coefficient(var)
            if not coeff.is_constant():
                raise ValueError(f"relation {rel}: coefficient of {var} is not constant (equation is not linear)")
            if not coeff.is_integer():
                raise ValueError(f"relation {rel}: coefficient of {var} is not an integer")

            coeffs.append(int(coeff) % m)

        # Shift variables towards their guesses to reduce the (expected) length of the solution vector
        const = expr.subs({var: guesses[var] for var in vars})
        if not const.is_constant():
            raise ValueError(f"relation {rel}: failed to extract constant")
        if not const.is_integer():
            raise ValueError(f"relation {rel}: constant is not integer")

        const = int(const) % m

        result.append((coeffs, const, m))

    return result


def solve_linear_mod(equations, bounds, verbose=False, **lll_args):
    """Solve an arbitrary system of modular linear equations over different moduli.

    equations: A sequence of (lhs == rhs, M) pairs, where lhs and rhs are expressions and M is the modulus.
    bounds: A dictionary of {var: B} entries, where var is a variable and B is the bounds on that variable.
        Bounds may be specified in one of three ways:
        - A single integer X: Variable is assumed to be uniformly distributed in [0, X] with an expected value of X/2.
        - A tuple of integers (X, Y): Variable is assumed to be uniformly distributed in [X, Y] with an expected value of (X + Y)/2.
        - A tuple of integers (X, E, Y): Variable is assumed to be bounded within [X, Y] with an expected value of E.
        All variables used in the equations must be bounded.
    verbose: set to True to enable additional output
    lll_args: Additional arguments passed to LLL, for advanced usage.

    NOTE: Bounds are *soft*. This function may return solutions above the bounds. If this happens, and the result
    is incorrect, make some bounds tighter and try again.

    Tip: if you get an unwanted solution, try setting the expected values to that solution to force this function
    to produce a different solution.

    Tip: if your bounds are loose and you just want small solutions, set the expected values to zero for all
    loosely-bounded variables.

    >>> k = var('k')
    >>> # solve CRT
    >>> solve_linear_mod([(k == 2, 3), (k == 4, 5), (k == 3, 7)], {k: 3*5*7})
    {k: 59}

    >>> x,y = var('x,y')
    >>> solve_linear_mod([(2*x + 3*y == 7, 11), (3*x + 5*y == 3, 13), (2*x + 5*y == 6, 143)], {x: 143, y: 143})
    {x: 62, y: 5}

    >>> x,y = var('x,y')
    >>> # we can also solve homogenous equations, provided the guesses are zeroed
    >>> solve_linear_mod([(2*x + 5*y == 0, 1337)], {x: 5, y: 5}, guesses={x: 0, y: 0})
    {x: 5, y: -2}
    """

    # The general idea is to set up an integer matrix equation Ax=y by introducing extra variables for the quotients,
    # then use LLL to solve the equation. We introduce extra axes in the lattice to observe the actual solution x,
    # which works so long as the solutions are known to be bounded (which is of course the case for modular equations).
    # Scaling factors are configured to generally push the smallest vectors to have zeros for the relations, and to
    # scale disparate variables to approximately the same base.

    vars = list(bounds)
    guesses = {}
    var_scale = {}
    for var in vars:
        bound = bounds[var]
        if isinstance(bound, Sequence):
            if len(bound) == 2:
                xmin, xmax = map(int, bound)
                guess = (xmax - xmin) // 2 + xmin
            elif len(bound) == 3:
                xmin, guess, xmax = map(int, bound)
            else:
                raise TypeError("Bounds must be integers, 2-tuples or 3-tuples")
        else:
            xmin = 0
            xmax = int(bound)
            guess = xmax // 2
        if not xmin <= guess <= xmax:
            raise ValueError(f"Bound for variable {var} is invalid ({xmin=} {guess=} {xmax=})")
        var_scale[var] = max(xmax - guess, guess - xmin, 1)
        guesses[var] = guess

    var_bits = math.log2(int(prod(var_scale.values()))) + len(vars)
    mod_bits = math.log2(int(prod(m for rel, m in equations)))
    if verbose:
        print(f"verbose: variable entropy: {var_bits:.2f} bits")
        print(f"verbose: modulus entropy: {mod_bits:.2f} bits")

    # Extract coefficients from equations
    equation_coeffs = _process_linear_equations(equations, vars, guesses)

    is_inhom = any(const != 0 for coeffs, const, m in equation_coeffs)

    NR = len(equation_coeffs)
    NV = len(vars)
    if is_inhom:
        # Add one dummy variable for the constant term.
        NV += 1
    B = matrix(ZZ, NR + NV, NR + NV)

    # B format (rows are the basis for the lattice):
    # [ mods:NRxNR 0
    #   eqns:NVxNR vars:NVxNV ]
    # eqns correspond to equation axes, fi(...) = yi mod mi
    # vars correspond to variable axes, which effectively "observe" elements of the solution vector (x in Ax=y)
    # mods and vars are diagonal, so this matrix is lower triangular.

    # Compute maximum scale factor over all variables
    S = max(var_scale.values())

    # Compute equation scale such that the bounded solution vector (equation columns all zero)
    # will be shorter than any vector that has a nonzero equation column
    eqS = S << (NR + NV + 1)
    # If the equation is underconstrained, add additional scaling to find a solution anyway
    if var_bits > mod_bits:
        eqS <<= int((var_bits - mod_bits) / NR) + 1
    col_scales = []

    for ri, (coeffs, const, m) in enumerate(equation_coeffs):
        for vi, c in enumerate(coeffs):
            B[NR + vi, ri] = c
        if is_inhom:
            B[NR + NV - 1, ri] = const
        col_scales.append(eqS)
        B[ri, ri] = m

    # Compute per-variable scale such that the variable axes are scaled roughly equally
    for vi, var in enumerate(vars):
        col_scales.append(S // var_scale[var])
        # Fill in vars block of B
        B[NR + vi, NR + vi] = 1

    if is_inhom:
        # Const block: effectively, this is a bound of 1 on the constant term
        col_scales.append(S)
        B[NR + NV - 1, -1] = 1

    if verbose:
        print("verbose: scaling shifts:", [math.log2(int(s)) for s in col_scales])
        print("verbose: unscaled matrix before:")
        print(B.n())

    for i, s in enumerate(col_scales):
        B[:, i] *= s
    B = B.LLL(**lll_args)
    for i, s in enumerate(col_scales):
        B[:, i] /= s

    # Negate rows for more readable output
    for i in range(B.nrows()):
        if sum(x < 0 for x in B[i, :]) > sum(x > 0 for x in B[i, :]):
            B[i, :] *= -1
        if is_inhom and B[i, -1] < 0:
            B[i, :] *= -1

    if verbose:
        print("verbose: unscaled matrix after:")
        print(B.n())

    for row in B:
        if any(x != 0 for x in row[:NR]):
            # invalid solution: some relations are nonzero
            continue

        if is_inhom:
            # Each row is a potential solution, but some rows may not carry a constant.
            if row[-1] != 1:
                if verbose:
                    print(
                        "verbose: zero solution",
                        {var: row[NR + vi] for vi, var in enumerate(vars) if row[NR + vi] != 0},
                    )
                continue

        res = {}
        for vi, var in enumerate(vars):
            res[var] = row[NR + vi] + guesses[var]

        return res
a = 29089145861698849533587576973295257566874181013683093409280511461881508560043226639624028591697075777027609041083214241167067154846780379410457325384136774173540880680703437648293957784878985818376432013647415210955529162712672841319668120257447461567038004250028029752246949587461150846214998661348798142220559280403267581983191669260262076357617420472179861844334505141503479938585740507007167412328247901645653025038188426412803561167311075415186139406418297360055617953651023218144335111178729068397052382593835592142212067930715544738880011596139654527770961911784544010189290315677772431190278256579916333137165255075163459126978209678330136547554839703581615386678643718339211024128344190549574517564644382447611744798875041346881354781693931986615205673317996958906543168487424513288646586386898335386252942417294351991435595389041536593887748040184886941013614961741810729168951559211294246606230105751075721451317188926451002620849423314518170658209171671914315184519999959495351937563075042077266900864146159426562183965523296477064353921084645981585062809887031916148806349242025315612913825933164149679421566262446757892475611986630543538188150542432463200651189833933982458007114429715435568714619661080138790893459960671301328455259702189597680258358027148120577359065875450633562059381985788036798654456426180261922908112060328808638698523351620789566317389045953829508142189900185007810978556531031234520426854056485675147172190502028351264431318960694075186507102430581156550179324060430995652420952731818727684039692796018771140481392835706804763480391403219506727895338895364591606497253163676677638669786786858737497920439433198267927890300667623673919500396414839378381934354516285899285278671196050670328000271445003863863854641343057226519772851093922041622949244909881042639419520750870739146022239848882362576253955639971615811326995401478442990402656532205515168792715334542129193521733882886780427236290633270965571593377055933030570964314193668632743086843644521712276882644432083012275643889490106050284317873072564495246844741833922331897169054478543498374111011001360629887265387016903
b = 23842135454777432891743223391138265563241799870175456642327123278749657522050965688647025271946838603033997215457359121062031090678062337376719430593135764515364544052891212988546634081941717578522276652565205405071925932782899189391582928430745625545751168223235578140422316604775465116636679365817463642606682382103650151553859378443311951637645862682606805670610169631771916714125895199501221576523042203542953632992797
n = 11325979084644128572298911896847368512066889699114922766957825496829789701040409280284912163337390977205935027654824418075908113980923567819511384456223871894254826496727684822147076089401320253972280078822901143659851738555573580052473815798989309369428595758953805619194262607259107358103749807085316873971927412767250429330952340169403993890298557816024130952523480708504075717017477
c = 91637278981727419311704062766528605893241365739887714388981571071807672497690225964001055671982318124750997320763003521883860470498708606433206468782382765369836856610266602374015551078759628514665188339252922366320922478645026704734702460355236791287112842409076450962765866362852307351865564192898522584768904066046337899302561685937649000409332117647123
coeff = [var(f"x_{i}") for i in range(6)]

def gen_data(coeff, p,length):
    
    return sum([coeff[i]*p**i for i in range(length)])

f = gen_data(coeff, b, 6) - a
b = {i: (-2**32,2**32) for i in coeff}
coeff = [_ for _ in solve_linear_mod([[f == 0, n]], b).values()]

F.<x> = PolynomialRing(GF(n))
f = gen_data(coeff, x, 6) - c
print(long_to_bytes(int(f.roots()[0][0])))