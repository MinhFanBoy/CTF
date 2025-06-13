
import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
from Crypto.Cipher import AES

io = process(["sage", "chall.sage"])
# io = remote("13.233.255.238", 4004)
# io.interactive()
e2, e3 = 216, 137
a, b = 216, 137
p = 2**e2 * 3**e3 - 1
F = GF(p**2, modulus=[1,0,1], name = "i")
i = F.gen()

def generate_torsion_basis(E, l, e, cofactor):
    while True:
        P = cofactor * E.random_point()
        if (l^(e-1)) * P != 0: 
            break
    while True:
        Q = cofactor * E.random_point()
        if (l^(e-1)) * Q != 0 and P.weil_pairing(Q, l^e) != 1:
            break
    return P, Q

def comp_iso(E, Ss, l, e):
    φ,  E1 = None, E
    for k in range(e):
        R = [l**(e-k-1) * S for S in Ss]
        ϕk = E1.isogeny(kernel=R)
        Ss = [ϕk(S) for S in Ss]
        E1 = ϕk.codomain()
        φ  = ϕk if φ is None else ϕk * φ
    return φ, E1

def j_ex(E, sk, pk, l, e):
    φ, _ = comp_iso(E, [pk[0] + sk*pk[1]], l, e)
    return φ.codomain().j_invariant()

def decrypt_flag(iv :str, ct: str, ss: bytes):
    iv = bytes.fromhex(iv)
    ct = bytes.fromhex(ct)
    key = hashlib.sha256(ss).digest()[:16]
    c  = AES.new(key, AES.MODE_CBC, iv)
    return c.decrypt(ct)

io.recvuntil(b"PA: ")
PA = eval(io.recvline())
io.recvuntil(b"QA: ")
QA = eval(io.recvline())
io.recvuntil(b"PB: ")
PB = eval(io.recvline())
io.recvuntil(b"QB: ")
QB = eval(io.recvline())
io.recvuntil(b"EA invariants: ")
EA_invariants = eval(io.recvline())
io.recvuntil(b"APB: ")
φAPB = eval(io.recvline())
io.recvuntil(b"AQB: ")
φAQB = eval(io.recvline())
io.recvuntil(b"APA: ")
φAPA = eval(io.recvline())
io.recvuntil(b"AQA: ")
φAQA = eval(io.recvline())
io.recvuntil(b"EB invariants: ")
EB_invariants = eval(io.recvline())
io.recvuntil(b"BPA: ")
φBPA = eval(io.recvline())
io.recvuntil(b"BQA: ")
φBQA = eval(io.recvline())

io.recvuntil(b"IV1: ")
iv1 = str(io.recvline()).replace("b'", "")[:-3]
io.recvuntil(b"CT1: ")
ct1 = str(io.recvline()).replace("b'", "")[:-3]
io.recvuntil(b"IV2: ")
iv2 = str(io.recvline()).replace("b'", "")[:-3]
io.recvuntil(b"CT2: ")
ct2 = str(io.recvline()).replace("b'", "")[:-3]
print(f"{iv1 = }")
print(f"{ct1 = }")
print(f"{iv2 = }")
print(f"{ct2 = }")

E0 = EllipticCurve(F, [0,6,0,1,0])
EA = EllipticCurve(F, EA_invariants)
EB = EllipticCurve(F, EB_invariants)

PA = E0(PA)
P3 = E0(PB)
QA = E0(QA)
Q3 = E0(QB)

φAPB = EA(φAPB)
φAQB = EA(φAQB)
φAPA = EA(φAPA)
φAQA = EA(φAQA)

φBPA = EB(φBPA)
φBQA = EB(φBQA)
