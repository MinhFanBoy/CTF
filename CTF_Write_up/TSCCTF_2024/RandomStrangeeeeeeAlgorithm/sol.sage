
import os

set_verbose(0)
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'linux'

import random
import sys
from Crypto.Util.number import *
from gmpy2 import iroot
from pwn import *


for _ in range(4096):
    i = process(["python", "server.py"])
    n, e = eval(i.recvline().strip().split(b' = ')[1])
    c = int(i.recvline().strip().split(b' = ')[1])

    S = 3 * (int(iroot(c, 3)[0]) ^ 2)

    M = matrix([
        [n, S], 
        [-e, 0]
    ]).LLL()

    k = M[0][1] // S
    s = (M[0][0] - 1) // k
    phi = n - s - 1

    d = inverse(e, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))
