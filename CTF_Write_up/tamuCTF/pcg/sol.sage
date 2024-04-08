
from pwn import *
from secrets import randbelow
from Crypto.Util.number import getPrime
from colorama import *

class PCG: # Polynomial Congruential Generator

    def __init__(self):
        self.m = getPrime(256)
        self.coeff = [randbelow(self.m-1) for _ in range(256)]
        self.x = randbelow(self.m-1)

    def __call__(self):
        newx = 0
        for c in self.coeff:
            newx *= self.x
            newx += c
            newx %= self.m
        self.x = newx
        return self.x



s = remote("tamuctf.com", 443, ssl=True, sni="pcg")

print(Fore.CYAN + f"[+] Starting...")
size = 256

m = int(s.recvline()[:-1].decode())

lst = []
for i in range(size * 3):

    lst.append(int(s.recvline()[:-1].decode()))


print(f"[+] Solving... (this may take a while)")

M = Matrix(Zmod(m), [[pow(x, size - 1 - i) for i in range(size)] for x in lst[:-1]])
e = vector(Zmod(m), lst[1:])

print(f"[+] Done!")

coeff = M.solve_right(e)
pcg = PCG()
pcg.m = m
pcg.coeff = [int(x) for x in coeff]
pcg.x = int(lst[-1])


print(f"[+] Sending...")
for i in range(size // 2):
    s.sendline(str(pcg()))

print(s.recvline())

print(f"[+] Done! go off")