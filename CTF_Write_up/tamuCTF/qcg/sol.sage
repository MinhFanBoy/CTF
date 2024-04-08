
from pwn import *
from Crypto.Util.number import *
from colorama import *

class QCG:
    def __init__(self, m, a, b, c, x):
        self.m = m
        self.a = a 
        self.b = b
        self.c = c
        self.x = x

    def __call__(self):
        self.x = (self.a*self.x**2+self.b*self.x+self.c) % self.m
        return self.x

s = remote("tamuctf.com", 443, ssl=True, sni="qcg")

ct = [ int(x.decode()) for x in s.recv().split(b"\n")[:-1]]
print(Fore.CYAN)
print(f"[+] Starting...")

PR.<a,b,c> = PolynomialRing(ZZ,order='lex')
I = ideal(a*ct[0]^2 + b*ct[0] + c - ct[1],
          a*ct[1]^2 + b*ct[1] + c - ct[2],
          a*ct[2]^2 + b*ct[2] + c - ct[3],
          a*ct[3]^2 + b*ct[3] + c - ct[4],
          a*ct[4]^2 + b*ct[4] + c - ct[5],
          a*ct[5]^2 + b*ct[5] + c - ct[6],
          a*ct[6]^2 + b*ct[6] + c - ct[7],
          a*ct[7]^2 + b*ct[7] + c - ct[8],
          a*ct[8]^2 + b*ct[8] + c - ct[9])

m = ZZ(I.groebner_basis()[-1])

M = Matrix(Zmod(m), [[pow(i, 2, m), i, 1] for i in ct[:-1]])
e = vector(Zmod(m), ct[1:])
coeff = M.solve_right(e)

qcg = QCG(m, int(coeff[0]), int(coeff[1]), int(coeff[2]), ct[-1])

print(f"[+] Sending...")
for i in range(5):
    s.sendline(str(qcg()))

print(s.recvline())
print(f"[+] Done! go off")