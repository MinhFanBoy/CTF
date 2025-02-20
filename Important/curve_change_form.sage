

"""

Montogomery: B * y^2 = x^3 + A * x^2 + x mod p
Weierstrass: v^2 = u^3 + a * u + b mod p
Twisted Edwards: a * u^2 + v^2 = 1 + d * (u * v)^2 mod p

"""

def twisted_Edwards_to_Montgomery(C):
    a, d, p = C
    A, B = (2 * (a + d) * pow(a - d, -1, p)) % p, (4 * pow(a - d, -1, p)) % p
    return (A, B, p)

def Montgomery_to_twisted_Edwards(C):
    A, B, p = C
    a, d = (A + 2) * pow(B, -1, p), (A - 2) * pow(B, -1, p)
    return (a, d, p)

def Montgomery_to_Short_Weierstrass(C):
    A, B, p = C
    a = ((3 - A ** 2) * pow(3 * B ** 2, -1, p)) % p
    b = ((2 * (A ** 3) - 9 * A) * pow(27 * B ** 3, -1, p)) % p
    return a, b, p

def change_point_from_twisted_Edwards_to_Montgomery(P, C):
    a, d, p = C
    u, v = P
    x_, y_ = ((1 + v) * pow(1 - v, -1, p)) % p, ((1 + v) * pow((1 - v) * u, -1, p) % p) % p
    return int(x_) % p, int(y_) % p

def change_point_from_Montgomery_to_Short_Weierstrass(P, C):
    A, B, p = C
    x, y = P
    x_, y_ = ((x + A * pow(3, -1, p)) * pow(B, -1, p)) % p, (y * pow(B, -1, p)) % p
    return int(x_) % p, int(y_) % p

def change_point_from_Montogomery_to_twisted_Edwards(P, C):
    A, B, p = C
    x, y = P
    u = (x) * pow(y, -1, p)
    v = (x - 1) * pow((1 + x), -1, p)
    return int(u) % p, int(v) % p

def change_point_from_Short_Weierstrass_to_Montgomery(P, C):
    a, b, p = C
    x, y = P
    x_, y_ = (3 * x + a) * pow(2 * y, -1, p), (2 * y) * pow(3 * x + a, -1, p)
    return int(x_) % p, int(y_) % p
def change_point_from_twisted_Edwards_to__Short_Weierstrass(sG):
    sG = change_point_from_twisted_Edwards_to_Montgomery(sG, (a, d, p))
    sG = change_point_from_Montgomery_to_Short_Weierstrass(sG, C_)
    return sG

def is_on_twisted_Edwards(P, C):

    u, v = P
    a, d, p = C
    
    # Tính vế trái: au^2 + v^2
    left = (a * pow(u, 2, p) + pow(v, 2, p)) % p
    
    # Tính vế phải: 1 + du^2v^2
    right = (1 + d * pow(u, 2, p) * pow(v, 2, p)) % p
    
    return left - right

def is_on_Montgomery(P, C):

    x, y = P
    A, B, p = C

    left = (B * pow(y, 2, p)) % p

    right = (pow(x, 3, p) + A * pow(x, 2, p) + x) % p
    
    return left - right

def is_on_Short_Weierstrass(P, C):

    x, y = P
    a, b, p = C
    
    left = pow(y, 2, p)
    right = (pow(x, 3, p) + a * x + b) % p
    
    return left - right
