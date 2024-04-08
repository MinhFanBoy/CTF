from gmpy2 import *
import math
from pwn import *
from tqdm import tqdm
from hashlib import sha256
from Crypto.Util.number import *

def lcm(a, b):
    return (a * b) // GCD(a, b)

def check(s,h,r,e,modulus):
    return (pow(s, e, modulus) - pow(h, 1, modulus) - pow(r, e, modulus)) % modulus


def sieve_of_eratosthenes_24bit():
    lower_limit = 2**23
    upper_limit = 2**24 
    primes = [True] * (upper_limit - lower_limit)

    for i in range(2, int(upper_limit ** 0.5) + 1):
        if primes[i]:
            for j in range(max(i*i, (lower_limit + i - 1) // i * i), upper_limit, i):
                primes[j - lower_limit] = False

    prime_numbers = [i for i in range(lower_limit, upper_limit) if primes[i - lower_limit]]
    return prime_numbers

io = remote("tamuctf.com", 443, ssl=True, sni="smooth-signatures")
e = 65537
io.recvuntil(b'\n',drop=True)
io.recvuntil(b'\n',drop=True)

res = io.recvuntil(b'Give the oracle a message to sign: ')
msg = b'Giang_dz_vcl'
io.sendline(msg)
io.recvuntil(b'Your verification signature is ')
res = io.recvuntil(b'\n',drop=True).decode()
r1,s1 = map(int, res.strip("()").split(","))

res = io.recvuntil(b'Give the oracle another message to sign: ')
msg = b'Giang_dz_vcl'
io.sendline(msg)
io.recvuntil(b'Your second verification signature is ')
res = io.recvuntil(b'\n',drop=True).decode()
r2,s2 = map(int, res.strip("()").split(","))
h = bytes_to_long(sha256(msg).digest())

# n = GCD(pow(s1,e)-h-pow(r1,e),pow(s2,e)-h-pow(r2,e))

primes = sieve_of_eratosthenes_24bit()
primes_n = []
n = 1
for i in tqdm(range(len(primes))):
    res1 = check(s1,h,r1,e,primes[i])
    res2 = check(s2,h,r2,e,primes[i])
    if res1 == 0 and res2 == 0:
        n= n*primes[i]
        primes_n.append(primes[i])

q = 1
for p in primes_n:
    q = lcm(q,p-1)
d = pow(e,-1,q)

io.recvuntil(b'Ask the oracle a question: ')
msg = b"What is the flag?"
io.sendline(msg)
h = bytes_to_long(sha256(msg).digest())
r = pow(h,d,n)
s = pow(2*h,d,n)
io.recvuntil(b"Give the verification signature: ")
send = str(r) + "," + str(s)
io.sendline(send.encode())
flag = io.recvuntil(b'\n',drop=True)
print(flag)