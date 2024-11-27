
# import os

# set_verbose(0)
# os.environ['PWNLIB_NOTERM'] = '1'
# os.environ['TERM'] = 'linux'

from sage.all import *
import json
from tqdm import trange
from secrets import randbelow
from Crypto.Util.number import *
from pwn import *
from params import *

s = process(["python3", "server.py"])

found = 1
while found:
    
    x = 2 * 2 * 2
    while x.bit_length() < 500:
        x *= getPrime(10)
    pq = []

    if 508 < x.bit_length() < 512:
        for i in trange(1 << (N - 1 - x.bit_length()), 1 <<  (N - x.bit_length())):
            if isPrime(x * i + 1):
                pq.append(int(x * i + 1))
            if len(pq) == 2 and pq[0].bit_length() == pq[1].bit_length() == N:
                print(pq)
                print(pq[0], pq[1], pq[0].bit_length(), pq[1].bit_length())
                found = 0
                break

q, p = pq
n = p ** 2 * q
g = n // 2

enc_xs = [1 + p for i in range(L)]
s.sendlineafter(b"> ", json.dumps({"n": n, "enc_xs": enc_xs}).encode())

params = json.loads(s.recvline().strip().decode())
enc_alphas, beta_sum_mod_n = params["enc_alphas"], params["beta_sum_mod_n"]

ys = []

k = gcd(p - 1, q - 1)

for e in enc_alphas:
    

    h1 = discrete_log(GF(p)(e), GF(p)(g))
    for i in trange(2, (q - 1) // k):
        tmp = crt([i, h1 % k], [(q - 1) // k, k])
        
        l_2 = discrete_log(GF(q)(pow(g, tmp, q)), GF(q)(1 + p))
        l_1 = discrete_log(GF(q)(e % q), GF(q)(1 + p))
        y = (l_1 - l_2) % (q - 1)
        
        if int(y).bit_length() <= 256:
            ys.append(int(y))
            break


s.sendlineafter(b"> ", json.dumps({"ys": [int(_) for _ in ys], "p": int(p), "q": int(q)}).encode())
print(s.recvline().strip().decode())  # Congratz! or Wrong...
print(s.recvline().strip().decode())  # flag or ys
