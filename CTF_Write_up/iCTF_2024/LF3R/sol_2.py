
from z3 import *
from tqdm import *
from Crypto.Util.number import long_to_bytes

class LF3R:
    def __init__(self, n, key, mask):
        self.n = n
        self.state = key & ((1 << n) - 1)
        self.mask = mask

    def __call__(self):
        v = self.state % 3
        self.state = (self.state >> 1) | (
            ((self.state & self.mask).bit_count() & 1) << (self.n - 1)
        )
        return v

n = 256
MASK = 0x560074275752B31E43E64E99D996BC7B5A8A3DAC8B472FE3B83E6C6DDB5A26E7
stream = [2, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 2, 2, 1, 1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 1, 2, 1, 0, 1, 0, 1, 0, 0, 0, 2, 2, 2, 0, 2, 1, 2, 0, 1, 1, 2, 1, 0, 0, 0, 0, 0, 2, 1, 2, 1, 2, 2, 1, 2, 2, 2, 2, 1, 0, 1, 0, 1, 0, 1, 2, 1, 2, 2, 1, 0, 0, 1, 2, 1, 2, 2, 1, 2, 1, 1, 1, 2, 2, 2, 1, 2, 1, 2, 0, 2, 2, 1, 2, 1, 1, 2, 1, 1, 0, 1, 1, 0, 2, 0, 2, 1, 2, 1, 2, 0, 1, 2, 1, 2, 1, 1, 2, 1, 2, 2, 0, 0, 2, 0, 0, 1, 2, 0, 2, 0, 1, 0, 2, 2, 1, 1, 2, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2, 2, 1, 1, 0, 2, 1, 2, 1, 1, 2, 1, 2, 1, 1, 2, 1, 1, 2, 1, 0, 0, 2, 1, 1, 1, 1, 2, 0, 0, 1, 2, 1, 2, 2, 1, 1, 1, 2, 1, 0, 0, 1, 0, 0, 2, 0, 2, 2, 1, 1, 2, 1, 2, 0, 2, 0, 1, 1, 1, 2, 1, 1, 0, 0, 0, 2, 2, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 2, 2, 1, 2, 1, 2, 0, 0, 0, 2, 1, 1, 2, 1, 1, 2, 1, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 2, 1, 0, 2, 0, 2, 1, 1, 2, 1, 1, 1, 1, 2, 1, 1, 2, 1, 2, 0, 2, 1, 2, 0, 2, 1, 1, 0, 1, 2, 0, 1, 2, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 2, 0, 1, 1, 2, 0, 2, 1, 1, 2, 1, 2, 0, 0, 1, 2, 2, 1, 2, 1, 1, 2, 1, 0, 2, 2, 2, 1, 1, 2, 2, 2, 0, 0, 1, 2, 0, 0, 0, 1, 2, 2, 2, 2, 2, 0, 1, 2, 1, 0, 2, 0, 1, 0, 0, 2, 1, 2, 1, 2, 1, 2, 1, 1, 2, 1, 2, 1, 1, 2, 0, 1, 2, 1, 2, 0, 0, 2, 2, 1, 2, 1, 1, 0, 2, 1, 0, 1, 1, 1, 0, 0, 1, 1, 2, 0, 1, 0, 2, 1, 2, 1, 2, 1, 2, 1, 1, 1, 2, 2, 0, 1, 2, 1, 2, 2, 2, 0, 0, 0, 0, 2, 1, 0, 1, 2, 2, 1, 0, 2, 1, 1, 2, 1, 2, 0, 0, 0, 0, 0, 1, 2, 1, 2, 0, 1, 2, 1, 1, 2, 1, 2, 1, 0, 2, 2, 2, 1, 2, 0, 2, 1, 1, 1, 0, 1, 1, 2, 2, 1, 2, 2, 2, 1, 0, 1, 2, 2, 1, 2, 0, 0, 0, 0, 0, 2, 1, 2, 0, 2, 1, 0, 2, 0, 1, 2, 0, 2, 1, 2, 1, 2, 1, 1, 2, 1, 2, 2, 1, 2, 2, 1, 1, 0, 0, 1, 0, 0, 2, 1, 2, 0, 0, 0, 1, 0, 1, 2, 1, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0, 1, 2, 1, 1, 0, 0, 2, 2, 0, 1, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0, 1, 1, 2, 1, 1, 1, 0, 0, 2, 1, 2, 1, 0, 0, 0, 2, 2, 0, 1, 1, 1, 2, 1, 2, 0, 0, 1, 2, 1, 2, 1, 0, 2, 0, 1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 1, 2, 0, 2, 1, 0, 0, 1, 0, 1, 0, 1, 1, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 2, 1, 0, 2, 2, 1, 2, 0, 0, 1, 1, 1, 2, 1, 1, 2, 1, 1, 2, 1, 1, 2, 0, 0, 1, 0, 1, 2, 2, 1, 2, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 2, 0, 2, 0, 2, 1, 1, 2, 0, 0, 1, 2, 1, 0, 0, 0, 2, 2, 1, 2, 1, 0, 0, 2, 1, 1, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 0, 0, 1, 0, 2, 0, 1, 2, 0, 2, 0, 0, 2, 1, 1, 1, 0, 0, 0, 1, 2, 1, 1, 0, 2, 1, 2, 1, 0, 1, 0, 0, 0, 1, 2, 0, 1, 2, 0, 0, 0, 1, 2, 1, 2, 0, 2, 1, 0, 0, 2, 2, 1, 1, 0, 0, 2, 0, 0, 0, 0, 0, 1, 2, 1, 2, 1, 0, 1, 1, 0, 0, 2, 1, 1, 1, 2, 0, 0, 1, 1, 0, 2, 2, 1, 0, 2, 1, 2, 1, 2, 0, 2, 1, 1, 1, 0, 0, 1, 2, 2, 2, 1, 0, 0, 1, 2, 1, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 1, 2, 1, 0, 2, 2, 0, 1, 1, 1, 1, 1, 2, 2, 0, 1, 2, 1, 0, 1, 1, 1, 2, 1, 0, 1, 1, 0, 0, 1, 2, 1, 1, 2, 0, 2, 0, 2, 1, 2, 2, 0, 0, 2, 1, 0, 1, 0, 2, 2, 1, 2, 2, 2, 0, 0, 0, 0, 2, 1, 0, 0, 1, 1, 0, 1, 1, 2, 2, 1, 0, 0, 0, 2, 2, 2, 1, 2, 1, 0, 2, 0, 0, 2, 2, 0, 2, 1, 1, 1, 0, 0, 1, 2, 0, 1, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 2, 0, 0, 1, 2, 1, 2, 2, 0, 1, 0, 0, 1, 1, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 1, 2, 1, 2, 1, 2, 0, 1, 2, 1, 0, 2, 0, 0, 2, 1, 2, 2, 1, 0, 1, 2, 2, 0, 0, 2, 0, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 2, 1, 1, 2, 2, 0, 1, 2, 0, 2, 1, 2, 2, 1, 0, 0, 0, 0, 2, 1, 2, 1, 1, 2, 1, 2, 1, 2, 2, 2, 0, 0, 0, 2, 2, 0, 0, 2, 1, 1, 2, 1, 0, 0, 0, 0, 1, 0, 1, 0, 2, 2, 0, 2, 0, 2, 0, 2, 2, 1, 2, 2, 2, 1, 0, 0, 0, 0, 2, 1, 2, 1, 2, 2, 1, 2, 0, 1, 1, 0, 2, 1, 0, 1, 0, 2, 1, 0, 2, 1, 2, 1, 1, 2, 1, 0, 0, 2, 0, 1, 1, 0, 0, 1, 0, 0, 2, 1, 0, 1, 0, 0, 1, 2, 1, 1, 2, 2, 0, 2, 1, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 2, 0, 2, 1, 2, 2, 2, 1, 1, 0, 1, 0, 2, 1, 2, 0, 0, 2, 2, 1, 0, 1, 2, 0, 0, 0, 0, 1, 2, 1, 2, 2, 0, 0, 0, 0, 1, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2, 2, 0, 0, 0, 0, 1, 2, 1, 1, 2, 1, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1, 2, 1, 1, 2, 1, 1, 2, 2, 1, 2, 2, 1, 1, 1, 1, 2, 0, 2, 2, 0, 1, 0, 2, 1, 0, 0, 0, 1, 2, 2, 0, 2, 1, 2, 2, 1, 0, 2, 1, 2, 1, 0, 0, 0, 0, 0, 1, 2, 1, 0, 2, 1, 1, 0, 0, 2, 0, 0, 0, 1, 1, 2, 1, 0, 2, 1, 2, 1, 2, 2, 1, 0, 0, 1, 2, 1, 2, 0, 2, 1, 2, 1, 1, 1, 1, 2, 1, 2, 2, 2, 1, 2, 2, 2, 0, 0, 0, 2, 1, 1, 1, 0, 1, 2, 2, 1, 0, 1, 2, 1, 2, 1, 0, 0, 0, 2, 2, 1, 1, 1, 1, 0, 0, 2, 1, 0, 0, 0, 0, 0, 1, 1, 1, 2, 2, 1, 2, 0, 2, 1, 2, 2, 2, 2, 1, 1, 1, 2, 0, 0, 0, 1, 2, 0, 0, 1, 1, 0, 1, 2, 0, 1, 0, 0, 1, 0, 2, 1, 1, 2, 0, 0, 1, 2, 0, 0, 2, 1, 2, 1, 0, 0, 2, 1, 2, 0, 0, 2, 1, 2, 2, 1, 2, 1, 1, 2, 1, 1, 2, 2, 0, 0, 1, 1, 2, 2, 2, 0, 0, 0, 0, 1, 2, 2, 2, 2, 1, 2, 2, 1, 1, 2, 1, 2, 1, 0, 2, 1, 2, 1, 2, 0, 2, 1, 0, 0, 1, 2, 1, 2, 0, 0, 0, 0, 2, 1, 2, 2, 2, 1, 2, 0, 0, 0, 2, 1, 2, 1, 0, 1, 2, 1, 0, 2, 1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 2, 2, 0, 0, 1, 2, 1, 0, 1, 1, 2, 1, 2, 1, 0, 2, 1, 0, 0, 1, 2, 1, 2, 0, 0, 1, 2, 2, 0, 1, 2, 0, 1, 0, 0, 0, 0, 0, 1, 2, 1, 1, 2, 1, 0, 0, 1, 2, 1, 0, 0, 2, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 2, 1, 2, 0, 0, 1, 2, 1, 2, 0, 0, 1, 2, 1, 0, 2, 0, 0, 2, 1, 1, 2, 2, 1, 1, 0, 2, 1, 0, 1, 1, 2, 2, 1, 2, 0, 0, 0, 1, 1, 1, 1, 0, 0, 2, 2, 1, 2, 1, 1, 0, 0, 1, 1, 2, 1, 2, 0, 0, 1, 0, 2, 1, 2, 2, 0, 1, 0, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 0, 2, 1, 2, 1, 2, 1, 2, 0, 1, 0, 1, 0, 1, 0, 2, 1, 2, 1, 2, 1, 2, 1, 0, 1, 2, 1, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0, 0, 2, 2, 1, 2, 0, 1, 0, 0, 1, 1, 2, 1, 2, 0, 0, 0, 2, 1, 0, 0, 1, 2, 2, 0, 0, 0, 1, 0, 2, 2, 1, 1, 2, 2, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 1, 2, 0, 0, 0, 1, 2, 1, 2, 1, 0, 0, 0, 2, 0, 2, 1, 0, 1, 1, 2, 1, 1, 2, 0, 2, 1, 2, 1, 1, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 1, 2, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 2, 2, 1, 1, 2, 1, 0, 1, 1, 2, 1, 2, 0, 1, 2, 1, 2, 1, 2, 0, 0, 2, 0, 2, 2, 1, 1, 1, 1, 1, 1, 2, 1, 0, 2, 1, 0, 0, 2, 0, 2, 1, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 2, 1, 2, 0, 2, 1, 1, 0, 0, 2, 0, 1, 2, 0, 0, 1, 2, 0, 0, 0, 0, 1, 2, 1, 0, 1, 1, 0, 0, 0, 1, 2, 2, 1, 0, 2, 0, 2, 1, 2, 0, 2, 1, 2, 1, 1, 0, 2, 0, 0, 0, 0, 0, 1, 1, 2, 2, 2, 2, 1, 0, 0, 0, 1, 1, 2, 0, 1, 1, 2, 0, 0, 0, 2, 1, 1, 1, 2, 0, 1, 0, 0, 2, 1, 0, 0, 0, 0, 2, 2, 0, 2, 1, 0, 0, 0, 2, 1, 2, 1, 2, 1, 2, 0, 0, 2, 1, 1, 1, 2, 2, 0, 2, 1, 2, 0, 2, 0, 2, 1, 0, 0, 0, 0, 2, 1, 1, 0, 1, 1, 1, 2, 2, 0, 2, 1, 2, 0, 2, 1, 1, 2, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 2, 0, 1, 1, 1, 2, 1, 0, 2, 1, 0, 0, 1, 1, 1, 1, 0, 1, 2, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0, 2, 2, 2, 0, 0, 0, 2, 2, 0, 2, 0, 2, 2, 0, 2, 1, 2, 2, 2, 0, 2, 1, 1, 1, 0, 2, 0, 0, 0, 1, 0, 2, 2, 0, 1, 0, 2, 1, 2, 2, 1, 0, 0, 1, 0, 2, 0, 2, 1, 0, 2, 0, 2, 2, 1, 0, 0, 0, 0, 2, 2, 2, 0, 2, 2, 1, 0, 0, 0, 2, 1, 1, 1, 0, 2, 2, 0, 2, 0, 2, 1, 0, 1, 2, 1, 1, 2, 1, 1, 1, 2, 1, 1, 0, 2, 2, 2, 2, 2, 1, 2, 1, 0, 1, 0, 1, 0, 1, 2, 2, 1, 2, 2, 1, 1, 2, 1, 1, 1, 1, 2, 0, 1, 2, 1, 0, 2, 0, 0, 2, 0, 2, 0, 1, 0, 0, 1, 2, 2, 2, 0, 1, 2, 1, 0, 0, 1, 1, 2, 0, 1, 1, 0, 2, 1, 0, 2, 2, 2, 0, 1, 2, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 2, 0, 1, 2, 0, 0, 0, 2, 0, 0, 1, 1, 1, 0, 2, 1, 2, 2, 2, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 2, 1, 2, 0, 1, 2, 0, 1, 2, 1, 2, 2, 1, 2, 0]

n = 256
step = 2048

"""

v = self.state % 3
self.state = (self.state >> 1) | (
    ((self.state & self.mask).bit_count() & 1) << (self.n - 1)
)

- c[i]: ((self.state & self.mask).bit_count() & 1) << (self.n - 1)
- xs[i] == 2 * (xs[i] >> 1) + (xs[i]&1)
1 << (self.n - 1) = 2 (mod 3), (xs[i] >> 1) + (2 if c else 0) == xs[i + 1]
"""

s = Solver()

v = [BitVec(f'v{i}', n) for i in range(step)]
c = [Bool(f'c{i}') for i in range(step - 1)]

for i in range(2):
    s.add(URem(v[i], 3) == stream[i])

for i in tqdm(range(step - 1)):
    
    tmp = LShR(v[i], 1)
    tmp = If(c[i], tmp | 1 << (n - 1), tmp)
    
    s.add(v[i + 1] == tmp)
    
    for guess in [0, 1]:
        for b in [False, True]:
            now = (stream[i + 1] * 2 + guess + (2 if b else 0)) % 3
            
            if (now != stream[i]):
                
                s.add(Or(v[i] & 1 != guess, c[i] != b))
                
r = s.check()
if r == sat:
    key = s.model()[v[0]].as_long()
else:
    print("Failed")
    exit()
lf3r = LF3R(n, key, MASK)
tmp = [lf3r() for _ in range(2048)]
lmao = ""
for o in stream[2048:]:
    lmao = lmao + str((o - lf3r()) % 3)

print(long_to_bytes(int(lmao[::-1], 3)))