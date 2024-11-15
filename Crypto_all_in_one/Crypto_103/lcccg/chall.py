
import secrets
from Crypto.Util.number import bytes_to_long

flag = b'paluctf{***********}'
class LCG:
    def __init__(self):
        self.x = secrets.randbits(64)
        self.a = 2
        self.m = secrets.randbits(64)

        while self.m % 2 == 0:
            self.m = secrets.randbits(64)

        print("m =", self.m)
    
    def next(self):
        self.x = (self.x * self.a) % self.m
        return self.x

lcg = LCG()

assert b"paluctf" in flag
f = bytes_to_long(flag)

l = f.bit_length()
print("length =", l)

r = 0
for i in range(l + 50):
    r += (lcg.next() & 1) << i

print("cipher =", r ^ f)
# m = 7870528503754256659
# length = 311
# cipher = 3255815260238431584829132773479447408817850185229659648404208268001256903206776002292220185602856730646093869
