import os
os.environ["TERM"] = "linux"
from pwn import *
loglevel = 'debug'
context.log_level = loglevel

import random
m = (1<<31) - 1

s = process(["go", "run", "main.go"])

o = []

for i in range(1, 6):
    s.recvuntil(f"Lucky number {i}: ")
    o.append(int(s.recvuntil(b"\n").decode().strip()))

def cacl(o):
    F.<a, b, c, d, e> = PolynomialRing(Zmod(m))

    k = []
    for i in range(5):
        y = (a*d + b*e + c)
        k.append(y)
        e = d
        d = y

    eq = []
    for _ in zip(k, o):
        eq.append(_[0] - _[1])
        

    I = ideal(eq)
    i = I.groebner_basis()

    if len(i) == 5:
        c_a = (-i[0].coefficients()[1]) % m
        c_b = (-i[1].coefficients()[1]) % m
        c_c = (-i[2].coefficients()[1]) % m
        c_d = (-i[3].coefficients()[1]) % m
        c_e = (-i[4].coefficients()[1]) % m
        print("a, b, c, d, e", c_a, c_b, c_c, c_d, c_e)
        return c_a, c_b, c_c, c_d, c_e
    return None

tmp = cacl(o)

if tmp:
    c_a, c_b, c_c, c_d, c_e = tmp
else:
    print("Error: Unable to calculate coefficients")
    exit(1)
    
for i in range(5):
    c_y = (c_a*c_d + c_b*c_e + c_c) % m
    c_e = c_d
    c_d = c_y
    
for i in range(23):
    c_y = (c_a*c_d + c_b*c_e + c_c) % m
    s.sendline(str(c_y).encode())
    c_e = c_d
    c_d = c_y

s.interactive()