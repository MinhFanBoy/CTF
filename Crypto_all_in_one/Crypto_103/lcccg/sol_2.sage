
from Crypto.Util.number import *

class LCG:
    def __init__(self, x, m):
        self.x = x
        self.a = 2
        self.m = m

    def next(self):
        self.x = (self.x * self.a) % self.m
        return self.x

m = 7870528503754256659
length = 311
cipher = 3255815260238431584829132773479447408817850185229659648404208268001256903206776002292220185602856730646093869
a = 2

form = b'paluctf{'
l = bytes_to_long(form).bit_length()

out = int(bin(cipher)[2:][:l + 50], 2) ^ bytes_to_long(form)

o = []

for i in range(out.bit_length()):
    o.append((out >> i) & 1)

l, r = 0, m

for i in o:
    
    mid = (r + l) >> 1
    
    if i:
        l = mid
    else:
        r = mid

for i in range(10):
    
    seed = l + i
    
    for i in range(361 - len(o)):
        seed = seed * inverse(2,m) % m
        
    lcg = LCG(seed, m)

    r = 0
    for i in range(length + 50):
        r += (lcg.next() & 1) << i

    print(long_to_bytes(r ^ cipher))
