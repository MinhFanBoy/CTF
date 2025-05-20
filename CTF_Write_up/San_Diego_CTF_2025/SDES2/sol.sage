
def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)

EXPONENT_BITS = 16
BASE_BITS = 32
NUM_BOXES = 8

N = 94879793147291298476721783294187445671264672494875032831129557319548520130487168324917679986052672729113562509486413401411372593283386734883795994908851074407159233933625803763510710542534207403621838561485897109991552457145707812125981258850253074177933543163534990455821426644577454934996432224034425315179
P = 270301083588606647149832441301256778567
EXPO_P = 13
SEED_BITS = 128
SEED_BYTES = SEED_BITS // 8

import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
# context.log_level = "debug"
s = process(["python3", "server.py"])

cts = []
es = []
for i in range(19):
    s.recvuntil(b"> ")
    s.sendline(b"e")
    s.recvuntil(b"> ")
    s.sendline(b"01")
    s.recvline()
    ciphertext = bytes.fromhex(s.recvline()[:-1].decode())
    header_len = SEED_BYTES
    header_bytes = ciphertext[:header_len]
    seed = int.from_bytes(header_bytes, byteorder="big")
    e = seed & ((1 << EXPONENT_BITS) - 1)
    exponent_schedule = [e]
    for _ in range(NUM_BOXES - 1):
        seed = pow(seed, EXPO_P, P)
        e = seed & ((1 << EXPONENT_BITS) - 1)
        exponent_schedule.append(e)
    ct_bytes = ciphertext[header_len:]
    ct = int.from_bytes(ct_bytes, byteorder="big")
    es.append(exponent_schedule)
    cts.append(ct)

M = matrix(es)

ks = block_matrix([
    [M, 1/ (1 << 512)]
])

ks = ks.LLL()
keys = [0 for _ in range(8)]
for i in ks:

    t = vector(list(i[8:])) * (1 << 512)
    out = t * M

    tmp = 1
    for _, __ in zip(list(t), cts):
        tmp *= pow(__, int(_), N)
    for i in range(8):
        if out[i] != 0:
            keys[i] = pow(tmp, int(out[i]), N)
            break

s.sendline(b"t")
s.recvuntil(b"Encrypted target message:")
s.recvline()

ciphertext = bytes.fromhex(s.recvline()[:-1].decode())
header_len = SEED_BYTES
header_bytes = ciphertext[:header_len]
seed = int.from_bytes(header_bytes, byteorder="big")
e = seed & ((1 << EXPONENT_BITS) - 1)
exponent_schedule = [e]
for _ in range(NUM_BOXES - 1):
    seed = pow(seed, EXPO_P, P)
    e = seed & ((1 << EXPONENT_BITS) - 1)
    exponent_schedule.append(e)
ct_bytes = ciphertext[header_len:]
ct = int.from_bytes(ct_bytes, byteorder="big")

pt = ct
for i, (box, e) in enumerate(zip(keys, exponent_schedule)):
    pt *= pow(keys[i], -e, N)

s.sendline(b"g")
s.sendline(hex(pt % N)[2:])
s.interactive()