

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_2 = Integer(2); _sage_const_3 = Integer(3); _sage_const_0 = Integer(0); _sage_const_1 = Integer(1); _sage_const_9 = Integer(9); _sage_const_126 = Integer(126); _sage_const_8 = Integer(8); _sage_const_127 = Integer(127); _sage_const_2024 = Integer(2024); _sage_const_10 = Integer(10)
from Crypto.Util.number import *
from random import *
import string

"""
Solve a bounded system of modular linear equations.

(c) 2019-2022 Robert Xiao <nneonneo@gmail.com>
https://robertxiao.ca

Originally developed in May 2019; updated July 2022

Please mention this software if it helps you solve a challenge!
"""

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
            if expr.degree(var) >= _sage_const_2 :
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
            if len(bound) == _sage_const_2 :
                xmin, xmax = map(int, bound)
                guess = (xmax - xmin) // _sage_const_2  + xmin
            elif len(bound) == _sage_const_3 :
                xmin, guess, xmax = map(int, bound)
            else:
                raise TypeError("Bounds must be integers, 2-tuples or 3-tuples")
        else:
            xmin = _sage_const_0 
            xmax = int(bound)
            guess = xmax // _sage_const_2 
        if not xmin <= guess <= xmax:
            raise ValueError(f"Bound for variable {var} is invalid ({xmin=} {guess=} {xmax=})")
        var_scale[var] = max(xmax - guess, guess - xmin, _sage_const_1 )
        guesses[var] = guess

    var_bits = math.log2(int(prod(var_scale.values()))) + len(vars)
    mod_bits = math.log2(int(prod(m for rel, m in equations)))
    if verbose:
        print(f"verbose: variable entropy: {var_bits:.2f} bits")
        print(f"verbose: modulus entropy: {mod_bits:.2f} bits")

    # Extract coefficients from equations
    equation_coeffs = _process_linear_equations(equations, vars, guesses)

    is_inhom = any(const != _sage_const_0  for coeffs, const, m in equation_coeffs)

    NR = len(equation_coeffs)
    NV = len(vars)
    if is_inhom:
        # Add one dummy variable for the constant term.
        NV += _sage_const_1 
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
    eqS = S << (NR + NV + _sage_const_1 )
    # If the equation is underconstrained, add additional scaling to find a solution anyway
    if var_bits > mod_bits:
        eqS <<= int((var_bits - mod_bits) / NR) + _sage_const_1 
    col_scales = []

    for ri, (coeffs, const, m) in enumerate(equation_coeffs):
        for vi, c in enumerate(coeffs):
            B[NR + vi, ri] = c
        if is_inhom:
            B[NR + NV - _sage_const_1 , ri] = const
        col_scales.append(eqS)
        B[ri, ri] = m

    # Compute per-variable scale such that the variable axes are scaled roughly equally
    for vi, var in enumerate(vars):
        col_scales.append(S // var_scale[var])
        # Fill in vars block of B
        B[NR + vi, NR + vi] = _sage_const_1 

    if is_inhom:
        # Const block: effectively, this is a bound of 1 on the constant term
        col_scales.append(S)
        B[NR + NV - _sage_const_1 , -_sage_const_1 ] = _sage_const_1 

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
        if sum(x < _sage_const_0  for x in B[i, :]) > sum(x > _sage_const_0  for x in B[i, :]):
            B[i, :] *= -_sage_const_1 
        if is_inhom and B[i, -_sage_const_1 ] < _sage_const_0 :
            B[i, :] *= -_sage_const_1 

    if verbose:
        print("verbose: unscaled matrix after:")
        print(B.n())

    for row in B:
        if any(x != _sage_const_0  for x in row[:NR]):
            # invalid solution: some relations are nonzero
            continue

        if is_inhom:
            # Each row is a potential solution, but some rows may not carry a constant.
            if row[-_sage_const_1 ] != _sage_const_1 :
                if verbose:
                    print(
                        "verbose: zero solution",
                        {var: row[NR + vi] for vi, var in enumerate(vars) if row[NR + vi] != _sage_const_0 },
                    )
                continue

        res = {}
        for vi, var in enumerate(vars):
            res[var] = row[NR + vi] + guesses[var]

        return res

class MRG:
    def __init__(self,para_len,p, a, b):
        self.init(para_len,p, a, b)

    def next(self):
        self.s = list(self.s[_sage_const_1 :]) + [(sum([i * j for (i, j) in zip(self.a, self.s)]) + self.b)]
        return self.s[-_sage_const_1 ]

    def init(self,para_len,p, a, b):
        F = PolynomialRing(Zmod(p), [f"x_{i}" for i in range(para_len)])
        self.p = p
        self.a = a
        self.b = b
        self.para_len = para_len
        # self.b = randint(1, self.p)
        # self.a = [randint(1, self.p) for i in range(para_len)]
        self.s = list(F.gens())
        self.s_ = list(F.gens())
        # self.s = [var(f"s{i}") for i in range(para_len)]
        # self.s_ = [var(f"s{i}") for i in range(para_len)]

    
    def get_params(self):
        return [self.a,self.b,self.s[_sage_const_0 ]]
    
    def sol(self, out):
        x = [var(f"x{i}") for i in range(self.para_len)]
        bound = {i: (_sage_const_9 , _sage_const_126 ) for i in x}
        f = sum(int(i) * j for i, j in zip(self.s[_sage_const_0 ].coefficients()[:-_sage_const_1 ], x)) - out + int(self.s[_sage_const_0 ].coefficients()[-_sage_const_1 ])
        l = solve_linear_mod([(f == _sage_const_0 , self.p)], bound)
        if l is None or not all( _sage_const_8  < _ < _sage_const_127  for _ in l.values()):
            return "1"
        return "0"
Round = _sage_const_2024 
A_len = _sage_const_10 
from tqdm import *
output = [i.strip() for i in open("output.txt", "r").readlines()]
p = int(output[_sage_const_0 ])
out = eval(output[_sage_const_1 ])
flag = ""
for a, b, o in tqdm(out):

    temp = MRG(A_len, p, a, b)
    temp.init(A_len, p, a, b)
    for j in range(Round):
        temp.next()
    flag += temp.sol(o)
from Crypto.Util.number import *
print(long_to_bytes(int(flag, _sage_const_2 )))
