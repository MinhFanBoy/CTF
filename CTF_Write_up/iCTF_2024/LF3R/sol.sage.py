

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_2 = Integer(2); _sage_const_0 = Integer(0); _sage_const_1 = Integer(1); _sage_const_2048 = Integer(2048); _sage_const_256 = Integer(256); _sage_const_3 = Integer(3); _sage_const_1560 = Integer(1560); _sage_const_255 = Integer(255)
from sage.all import *
from sage.matrix.berlekamp_massey import berlekamp_massey
import secrets, random, sys
from hashlib import sha256
from sage.crypto.boolean_function import BooleanFunction
from functools import lru_cache
from tqdm import tqdm, trange
from chall import MASK,LF3R
from binteger import Bin
F2 = GF(_sage_const_2 )
PR = PolynomialRing(F2, "x")
x = PR.gen()
stream = [_sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_2 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_1 , _sage_const_0 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_0 , _sage_const_1 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_2 , _sage_const_1 , _sage_const_2 , _sage_const_0 ]
stream = stream[:_sage_const_2048 ]
m = len(stream)


def mask_to_poly(mask, n):
    return PR(list(map(int, f"{mask:0{n}b}"[::-_sage_const_1 ]))) + x**n


def poly_to_eq(poly):
    return [i for i, v in enumerate(poly) if v]


def poly_to_mask(poly):
    return int(poly.change_ring(ZZ)(_sage_const_2 ) - _sage_const_2  ** poly.degree())

def vec_to_state_2(v):
    return int("".join(map(str, v)), _sage_const_2 )
def vec_to_state(v):
    return int("".join(map(str, v[::-_sage_const_1 ])), _sage_const_2 )
def get_linsys(feedback_poly, length):
    n = feedback_poly.degree()
    M = companion_matrix(feedback_poly, "bottom")
    # 1 ....
    #   1...
    #.....1
    # a1 a2 a3 ..
    Mn = M**n
    rows = []
    I = matrix.identity(n)
    for i in trange(length // n + _sage_const_1 , desc="Get linear system"):
        rows.extend(I.rows())
        I *= Mn
    return rows

f1 = mask_to_poly(MASK, _sage_const_256 )
print(f1)

linsys_14 = get_linsys(f1, m)

M1 = companion_matrix(f1, "bottom")
F2 = GF(_sage_const_3 )
PR = PolynomialRing(F2, "x")
x = PR.gen()
lhs = []
rhs = []
for x in range(len(stream) -_sage_const_1560 , len(stream)) :
    
    lhs.append(linsys_14[x])
    rhs.append(stream[x])
    if len(lhs) > _sage_const_255  :
        break
print(len(lhs))
key14 = matrix(lhs).solve_right(vector(rhs))
print(len(key14))
print(key14)
print(vec_to_state_2(key14))
print(vec_to_state(key14))
