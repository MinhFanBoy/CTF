

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_7870528503754256659 = Integer(7870528503754256659); _sage_const_311 = Integer(311); _sage_const_3255815260238431584829132773479447408817850185229659648404208268001256903206776002292220185602856730646093869 = Integer(3255815260238431584829132773479447408817850185229659648404208268001256903206776002292220185602856730646093869); _sage_const_2 = Integer(2); _sage_const_50 = Integer(50); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0)
from Crypto.Util.number import *
m = _sage_const_7870528503754256659 
length = _sage_const_311 
cipher = _sage_const_3255815260238431584829132773479447408817850185229659648404208268001256903206776002292220185602856730646093869 
a = _sage_const_2 

form = b'paluctf{'
l = bytes_to_long(form).bit_length()

out = int(bin(cipher)[_sage_const_2 :][:l + _sage_const_50 ], _sage_const_2 ) ^ bytes_to_long(form)

o = []

for i in range(out.bit_length()):
    o.append((out >> i) & _sage_const_1 )

rm, lm = _sage_const_1 , _sage_const_0 
r, l = m, _sage_const_0 

for _, i in enumerate(o):
    
    if i == _sage_const_1 :
        
        rm = _sage_const_2  * rm
        lm = _sage_const_2  * lm + _sage_const_1  
        
        r = min(r, rm * m // (_sage_const_2  ** (_ + _sage_const_1 )))
    else:
        
        rm = _sage_const_2  * rm - _sage_const_1 
        lm = _sage_const_2  * lm
        
        l = max(l, lm * m // (_sage_const_2  ** (_ + _sage_const_1 )))
print(r, l)

