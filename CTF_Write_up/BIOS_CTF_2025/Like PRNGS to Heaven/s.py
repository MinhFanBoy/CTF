
import os
os.environ["TERM"] = "linux"

from pwn import *
from Crypto.Util.number import *
from z3 import *
import json
from tinyec.ec import SubGroup, Curve
from RMT import R_MT19937_32bit as special_random
from decor import HP, death_message, menu_box, title_drop
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits
from hashlib import sha256
from json import loads
import sys
from tqdm import *

s = connect("13.233.255.238", 4002)
# s = process(["python3", 'chall.py'])
# s.interactive()

def supreme_RNG(seed: int, length: int = 10):
    while True:
        str_seed = str(seed) if len(str(seed)) % 2 == 0 else '0' + str(seed)
        sqn = str(seed**2)
        mid = len(str_seed) >> 1
        start = (len(sqn) >> 1) - mid
        end = (len(sqn) >> 1) + mid   
        yield sqn[start : end].zfill(length)
        seed = int(sqn[start : end]) 

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
h = 0x1
simple_lcg = lambda x: (x * 0xeccd4f4fea74c2b057dafe9c201bae658da461af44b5f04dd6470818429e043d + 0x8aaf15) % n
CORE = 0xb4587f9bd72e39c54d77b252f96890f2347ceff5cb6231dfaadb94336df08dfd
RNG_seed = simple_lcg(CORE)
n_gen = supreme_RNG(RNG_seed)
RNG_gen = next(n_gen)

def call_the_signer():
    s.recvuntil(b"Expecting Routine in JSON format: ")
    s.sendline(json.dumps({
        "event": "call_the_signer"
    }))
    s.sendline(b"0")
    Hmsg = sha256()
    Hmsg.update(b"0")
    s.recvuntil(b"What do you wish to speak? ")
    tmp = eval(s.recvline().strip())
    tmp["h"] = bytes_to_long(Hmsg.digest())
    return tmp

def perform_deadcoin():
    s.recvuntil(b"Expecting Routine in JSON format: ")
    s.sendline(json.dumps({
        "event": "perform_deadcoin"
    }))
    s.recvuntil(b": ")
    power, speed  = eval(s.recvline())

    feedbacker_parry = int(next(n_gen))
    style_bonus = feedbacker_parry ^ (feedbacker_parry >> 5)
    if power == pow(2, style_bonus, speed):
        s.sendline(str(feedbacker_parry).encode())
    s.recvuntil(b"ID: ")
    return int(s.recvline().strip().decode())

def get_encrypted_flag():
    s.recvuntil(b"Expecting Routine in JSON format: ")
    s.sendline(json.dumps({
        "event": "get_encrypted_flag"
    }))

    tmp = eval(s.recvline())
    return tmp

enc = (get_encrypted_flag())

from gf2bv import LinearSystem
def t(_and, eq):
    lin = LinearSystem([32])
    term = lin.gens()[0]
    zeros = [int(eq) ^ (term ^ ((term << 16) & int(_and)))]
    sol = lin.solve_one(zeros)
    print(int(eq) ^ (int(sol[0]) ^ ((int(sol[0]) << 16) & int(_and))))
    return sol[0]

def find_benjamin(c):
    return [t(*c[0]), t(*c[1])]

sig = []

from test_mersenne import *
from solve_linear import solve_linear_mod
for i in range(3):
    sig.append((i, perform_deadcoin()))

seed = test_seed_mt(sig)
Max_Sec = special_random(seed)
Max_Sec.get_num()
Max_Sec.get_num()
Max_Sec.get_num()
print(f"Seed: {seed}")

def sec_real_bits(bits: int) -> int:
    if bits % 32 != 0:
        raise ValueError("Bit length must be a multiple of 32")   
    exp = bits // 32
    x = Max_Sec.get_num() ** exp
    cyc_exhausted = 0
    while x.bit_length() != bits:
        x = Max_Sec.get_num() ** exp
        cyc_exhausted += 1
    return x

k_m1 = [var(f"m1_{_}") for _ in range(5)]
k_m2 = [var(f"m2_{_}") for _ in range(5)]
k_m3 = [var(f"m3_{_}") for _ in range(5)]
k_m4 = [var(f"m4_{_}") for _ in range(5)]

bound = {}
for i in range(5):
    bound[k_m1[i]] = (0, 1 << 24)
    bound[k_m2[i]] = (0, 1 << 24)
    bound[k_m3[i]] = (0, 1 << 69)
    bound[k_m4[i]] = (0, 1 << 30)

n_ = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
eqs = []

sig = (call_the_signer())
c = sig["nonce_gen_consts"]
benjamin1_, benjamin2_ = find_benjamin(c)
k_m5_ = sec_real_bits(32)
k_m6_ = sec_real_bits(32)
i = 0
const_list = [k_m1[i], (benjamin1_ >> 24 & 0xFF), k_m2[i], (benjamin1_ >> 16 & 0xFF) , k_m5_, (benjamin1_ >> 8 & 0xFF), k_m3[i], (benjamin1_ & 0xFF), k_m4[i], (benjamin2_ >> 24 & 0xFFF), k_m6_]
shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]
noncense = 0
for const, shift in zip(const_list, shift_list):
    noncense += const * (1 << shift)
k1 = noncense
r1_, s1_, h1_ = sig["r"], sig["s"], sig["h"]

for i in range(1, 5):
    k_m5 = sec_real_bits(32)
    k_m6 = sec_real_bits(32)
    sig = (call_the_signer())
    c = sig["nonce_gen_consts"]
    benjamin1, benjamin2 = find_benjamin(c)
    const_list = [k_m1[i], (benjamin1 >> 24 & 0xFF), k_m2[i], (benjamin1 >> 16 & 0xFF) , k_m5, (benjamin1 >> 8 & 0xFF), k_m3[i], (benjamin1 & 0xFF), k_m4[i], (benjamin2 >> 24 & 0xFFF), k_m6]
    shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]
    noncense = 0
    for const, shift in zip(const_list, shift_list):
        noncense += const * (1 << shift)
    r_, s_, h_ = sig["r"], sig["s"], sig["h"]

    eqs.append([r_ * k1 * s1_ - r1_ * noncense * s_ == r_ * h1_ - r1_ * h_, n_])

tmp = (solve_linear_mod(eqs, bound))
print(tmp)
i = 0
const_list = [tmp[k_m1[i]], (benjamin1_ >> 24 & 0xFF), tmp[k_m2[i]], (benjamin1_ >> 16 & 0xFF) , k_m5_, (benjamin1_ >> 8 & 0xFF), tmp[k_m3[i]], (benjamin1_ & 0xFF), tmp[k_m4[i]], (benjamin2_ >> 24 & 0xFFF), k_m6_]
shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]
noncense = 0
for const, shift in zip(const_list, shift_list):
    noncense += const * (1 << shift)

n_ = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
d = ((s1_ * noncense - h1_) * pow(r1_, -1, n_)) % n_

enc_flag = enc["ciphertext"]
iv = bytes.fromhex(enc["iv"])
enc_flag = bytes.fromhex(enc_flag)

sha2 = sha256()
sha2.update(str(d).encode('ascii'))
key = sha2.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
print(cipher.decrypt(enc_flag))
