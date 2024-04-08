from Crypto.Util.number import *
from gmpy2 import *
import math
from pwn import *
from tqdm import tqdm
from hashlib import sha256

def lcm(a, b):
    return (a * b) // GCD(a, b)
def check(s,h,r,e,modulus):
    return (pow(s, e, modulus) - pow(h, 1, modulus) - pow(r, e, modulus)) % modulus

def sieve_of_eratosthenes_24bit(lower_limit=2**23, upper_limit=2**24):

    primes = [True] * (upper_limit - lower_limit)

    for i in range(2, int(upper_limit ** 0.5) + 1):
        if primes[i]:
            for j in range(max(i*i, (lower_limit + i - 1) // i * i), upper_limit, i):
                primes[j - lower_limit] = False

    prime_numbers = [i for i in range(lower_limit, upper_limit) if primes[i - lower_limit]]
    return prime_numbers

s = remote("tamuctf.com", 443, ssl=True, sni="smooth-signatures")

print(f"[+] Starting...")
e = 65537
msg = b"hmm"
h = bytes_to_long(sha256(msg).digest())

s.recvuntil(b"Give the oracle a message to sign: ")
s.sendline(msg)
s.recvuntil(b"(")

enc_1 = [int(x) for x in s.recvuntil(b")")[:-1].decode().split(", ")]


s.recvuntil(b"Give the oracle another message to sign: ")
s.sendline(msg)
s.recvuntil(b"(")

enc_2 = [int(x) for x in s.recvuntil(b")")[:-1].decode().split(", ")]

primes = []

phi = 1
n = 1

print(f"[+] Finding primes...")
p = sieve_of_eratosthenes_24bit()
for i in tqdm(range(len(p))):
    res1 = check(enc_1[1], h, enc_1[0], e, p[i])
    res2 = check(enc_2[1], h, enc_2[0], e, p[i])
    if res1 == 0 and res2 == 0:
        n *= p[i]
        primes.append(p[i])
        phi *= (p[i] - 1)

print(f"[+] Found {len(primes)} primes")

h = bytes_to_long(sha256(b"What is the flag?").digest())

print(f"[+] Sending r,s...")

s.recvline()
s.recv()
s.sendline(b"What is the flag?")
s.recv()
s.sendline(f"{str(0)},{str(pow(h, pow(e, -1, phi), n))}".encode())
print(s.recv())

