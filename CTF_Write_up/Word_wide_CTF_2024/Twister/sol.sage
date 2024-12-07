
func = lambda a, b, x: RR(sin(x / a + b))
def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            elif BB[ii, jj] == 1:
                a += '1'
            elif BB[ii, jj] == -1:
                a += '-'
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)
from dataclasses import dataclass
from cmath import exp
import secrets
import time
import os
from tqdm import *

@dataclass
class Wave:
    a: int
    b: int

    def eval(self, x):
        return func(self.a, self.b, x)
    

import os

set_verbose(0)
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'linux'

from pwn import *

# context.log_level = 'debug'
# s = process(['python3', 'deploy.py'])
s = connect("twister.chal.wwctf.com", 1337)
l = []
for i in range(9):
    
    s.sendlineafter(">", str(1))
    s.recvuntil(b' You commited a fix deleting ')
    k = bin(int(s.recvuntil(b" ").strip()))[2:].zfill(32)
    for i in k:
        l.append(int(i))
    s.recvline()

# s.interactive()

ALL_WAVES = [Wave(a, b) for a in range(2, 32) for b in range(7)]
state = (1337, [1 for _ in ALL_WAVES])
point = state[0]
waves = [wave for wave, mask in zip(ALL_WAVES, state[1]) if mask]
q = 2
n = len(l)
L = [[] for i in range(n)]

for i in trange(n):

    for wave in waves:
        k = round(wave.eval(point + i))
        L[i].append(k)

M = matrix(GF(2), L)
V = vector(GF(2), l)

k = M.solve_right(V)
print(len(k.list()))
class MaximTwister:
    """
    Next-generation PRNG with really **complex** nature.
    More reliable than /dev/random cuz doesn't block ever.
    """

    def __init__(self, state=None):
        if state is None:
            state = (1337, k)

        self.point = state[0]
        self.waves = [wave for wave, mask in zip(ALL_WAVES, state[1]) if mask]

    def get_randbit(self) -> int:
        result = 0
        for wave in self.waves:
            # you would never decompose a sum of waves 😈
            result += round(wave.eval(self.point))
        # especially if you know only the remainder, right? give up
        result %= 2
        self.point += 1

        return result

    def get_randbits(self, k: int) -> int:
        return int("".join(str(self.get_randbit()) for _ in range(k)), 2)

    def get_token_bytes(self, k: int) -> bytes:
        return bytes([self.get_randbits(8) for _ in range(k)])

random = MaximTwister((1337, list(k)))
for i in range(9):
    random.get_randbits(32)

s.sendlineafter(">", str(2))
s.recvline()
x = random.get_token_bytes(16)
s.sendlineafter(">", x.hex())

s.interactive()