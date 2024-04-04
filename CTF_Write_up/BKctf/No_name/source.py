#!/usr/bin/python3
from Crypto.Util.number import getPrime
import os

flag = "BKSEC{***************}"
m = int(flag.encode().hex(), 16)

p = getPrime(512)
q = getPrime(512)

n = p*q

print("n =", n)
print("a =", pow(m, p, n))
print("b =", pow(m, q, n))
print("c =", pow(m, n, n))
