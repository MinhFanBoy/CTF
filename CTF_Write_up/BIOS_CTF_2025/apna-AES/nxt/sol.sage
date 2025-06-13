
from hashlib import sha256
from Crypto.Util.number import inverse

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Q_x = 75734809163232403156751567099323868969251536315520212930406362087044311009812
Q_y = 59376216810615307969183220664321477461374978580814681880833956961200252954411
r = 75188570313431311860804303251549254089807291132108761029130443888999271228837
s = 28425244802253213823226413962559295239693382541446853572606143356013575587849

E = EllipticCurve(GF(p), [0, 7])
G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
Q = E(Q_x, Q_y)

h = int(sha256(b"Karmany-evadhikaras te ma phalesu kadacana ma karma-phala-hetur bhur ma te sango 'stv akarmani.").hexdigest(), 16)

F.<d_h, d_l> = PolynomialRing(Zmod(n))

f = s * (int(h >> 128) * (1 << 128) + d_h) - (h + r * (d_l + d_h * (1 << 128)))

M = list(f.coefficients())

M = block_matrix(ZZ, [
    [matrix(M).T, 1], 
    [n, 0]
])

w = diagonal_matrix([1, 1 << 128, 1 << 128, 1], sparse=0)

M /= w
M = M.BKZ()
M *= w

for i in M:
    if i[0] == 0 and abs(i[-1]) == 1:
        d_h = abs(i[1])
        d_l = abs(i[2])
        break


d = d_l + d_h * (1 << 128)
flag = sha256(str(d).encode()).hexdigest()
print(f"bi0sCTF{{{flag}}}")