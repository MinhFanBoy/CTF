
from pwn import *
import json
import paillier
import ecc
import dlnproof

from secrets import randbelow
from Crypto.Util.number import *

from secret import flag, P, Q
from mta import *

s = process(["python3", 'server.py'])

NTildeA = P * Q
Lambda = (P-1)*(Q-1) // 4

print(s.recv())
print(s.recvuntil(b"="))

apub = eval(s.recvline())
print(s.recvuntil(b"Bob Public Key = "))

bpub = {
    "NTildeB": 1,
    "h1B": 1,
    "h2B": 1,
    "dlnproof": [
        dlnproof.getDLNProof(1, 1, 1, 2, 2),
        dlnproof.getDLNProof(1, 1, 1, 2, 2),
    ]}
s.sendline(json.dumps(bpub))

print(s.recv())
print(s.recv())
print(s.recv())