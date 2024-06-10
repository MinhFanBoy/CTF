
# assert(2*f_second_prime - 6*f_prime + 3*f == 0)
# assert(f.subs(x, 0) | f_prime.subs(x, 0) == 14)
P.<x> = PolynomialRing(ZZ)
f = x**2 - (3)*x + 1.5

print(f.roots())