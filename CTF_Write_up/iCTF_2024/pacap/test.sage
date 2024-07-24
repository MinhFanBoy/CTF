# Define the variables
PR = PolynomialRing(ZZ, ["x", "y", "z"])
x, y, z = PR.gens()

# Define the cubic polynomial
c = 3

# Transform the cubic polynomial into an elliptic curve
E = EllipticCurve_from_cubic( x^3 + c*y^3 + c^2*z^3 - 3*c*x*y*z - 1 == 0)
print(E)
