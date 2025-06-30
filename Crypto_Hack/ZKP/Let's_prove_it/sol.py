
#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime
import hashlib
import random
import os
import string
from pwn import *
import json

FLAG = b"crypto{??????????????????????????????}"

BITS = 2 << 9
g = 2

class Proof:
    def __init__(self, seed, nonce):
        global FLAG
        self.nonce = nonce
        self.seed = long_to_bytes(seed)
        self.refresh(seed)
        self.prime = self.fiatShamir()
    def getPrime(self, N):
        while True:
            number = self.R.getrandbits(N) | 1
            if isPrime(number, randfunc=lambda x: long_to_bytes(self.R.getrandbits(x))):
                break
        return number

    def refresh(self, seed):
        self.R = random.Random(self.nonce + self.seed)

    def fiatShamir(self):
        p = self.getPrime(BITS)
        return p

primes = []
lst = []
your_turn = 1
turn = 0
s = connect("socket.cryptohack.org", 13430)

s.recvuntil(b"nonce for this instance: ")

nonce = bytes.fromhex(s.recvline().decode().strip())
i = 17
while turn < 12:
    
    if your_turn == 2:
        s.sendline(json.dumps({"option": "refresh", "seed": hex(i)[2:]}).encode())
        primes.append(Proof(i, nonce).prime)
        your_turn = 0
        i += 1
        s.recvline()
    else:
        
        s.sendline(json.dumps({"option": "get_proof"}).encode())
        tmp = s.recvline().decode().strip()
        tmp = json.loads(tmp)
        if your_turn == 0:
            
            c = bytes_to_long(hashlib.sha3_256(long_to_bytes(tmp["t"] ^ tmp["y"] ^ tmp["g"])).digest()) ** 2
            lst.append([tmp["y"], tmp["t"],tmp["r"], c])
        your_turn += 1
        turn += 1

print(primes)
print(lst)
print(nonce)