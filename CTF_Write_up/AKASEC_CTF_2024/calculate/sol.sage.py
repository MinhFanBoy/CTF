

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_2 = Integer(2); _sage_const_3 = Integer(3); _sage_const_1p5 = RealNumber('1.5')
# assert(2*f_second_prime - 6*f_prime + 3*f == 0)
# assert(f.subs(x, 0) | f_prime.subs(x, 0) == 14)
P = PolynomialRing(ZZ, names=('x',)); (x,) = P._first_ngens(1)
f = x**_sage_const_2  - (_sage_const_3 )*x + + _sage_const_1p5 

print(f.roots())

