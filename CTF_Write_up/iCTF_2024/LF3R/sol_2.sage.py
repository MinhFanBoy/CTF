

# This file was *autogenerated* from the file sol_2.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1 = Integer(1); _sage_const_3 = Integer(3); _sage_const_256 = Integer(256); _sage_const_0x560074275752B31E43E64E99D996BC7B5A8A3DAC8B472FE3B83E6C6DDB5A26E7 = Integer(0x560074275752B31E43E64E99D996BC7B5A8A3DAC8B472FE3B83E6C6DDB5A26E7); _sage_const_2 = Integer(2); _sage_const_0 = Integer(0); _sage_const_2048 = Integer(2048)
from z3 import *
from tqdm import *

class LF3R:
    def __init__(self, n, key, mask):
        self.n = n
        self.state = key & ((_sage_const_1  << n) - _sage_const_1 )
        self.mask = mask

    def __call__(self):
        v = self.state % _sage_const_3 
        self.state = (self.state >> _sage_const_1 ) | (
            ((self.state & self.mask).bit_count() & _sage_const_1 ) << (self.n - _sage_const_1 )
        )
        return v

def int_to_base(n, b):
    digits = []
    while n:
        digits.append(n % b)
        n //= b
    return digits

n = _sage_const_256 
MASK = _sage_const_0x560074275752B31E43E64E99D996BC7B5A8A3DAC8B472FE3B83E6C6DDB5A26E7 
stream = [_sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 ]

n = _sage_const_256 
step = _sage_const_2048 

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
c = [BitVec(f'v{i}', _sage_const_1 ) for i in range(step)]

for i in tqdm(range(step - _sage_const_1 )):
    
    tmp = LFsR(v[i], _sage_const_1 )
    tmp = If(c[i], tmp | _sage_const_1  << (n - _sage_const_1 ), tmp)
    
    s.add(v[i + _sage_const_1 ] == tmp)
    
    for guess in [_sage_const_0 , _sage_const_1 ]:
        for i in [_sage_const_0 , _sage_const_1 ]:
            now = stream[i + _sage_const_1 ] * _sage_const_2  + guess + (_sage_const_2  if i else _sage_const_0 ) % _sage_const_3 
            
            if (now != stream[i]):
                
                s.add(Or(v[i] & _sage_const_1  != guess, c[i] != guess))
                
print(s.check())
