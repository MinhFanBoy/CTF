from Crypto.Util.number import *
m = 7870528503754256659
length = 311
cipher = 3255815260238431584829132773479447408817850185229659648404208268001256903206776002292220185602856730646093869
a = 2

form = b'paluctf{'
l = bytes_to_long(form).bit_length()

out = int(bin(cipher)[2:][:l + 50], 2) ^^ bytes_to_long(form)

o = []

for i in range(out.bit_length()):
    o.append((out >> i) & 1)

rm, lm = 1, 0
r, l = m, 0

for _, i in enumerate(o):
    
    if i == 1:
        
        rm = 2 * rm
        lm = 2 * lm + 1 
        
        r = min(r, rm * m // (2 ** (_ + 1)))
    else:
        
        rm = 2 * rm - 1
        lm = 2 * lm
        
        l = max(l, lm * m // (2 ** (_ + 1)))
print(r, l)