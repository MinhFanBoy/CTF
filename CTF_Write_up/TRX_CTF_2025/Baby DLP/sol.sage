from hashlib import sha256
from binascii import crc32
import re
from Crypto.Util.number import bytes_to_long, long_to_bytes
from random import randint
import itertools
from sage.all import *

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

os.environ["TERM"] = "xterm-256color"

from pwn import *

m = 0x05ab035976b887b505bfcc20df74d9ab3d4a50cb87f5cede0d
# s = process(["sage", "chal.sage"])
s= connect("babydlp.ctf.theromanxpl0.it", 7002)

# context.log_level = "DEBUG"

def get_enc():
    s.sendline(b"1")
    s.sendline(b"1")
    s.recvuntil(b"Here is the signature:\n")
    # print(s.recvline())
    R = eval(s.recvline().decode().strip().split(" = ")[1])
    s_ = int(s.recvline().decode().strip().split(" = ")[1])
    return R[0], s_

h = int(sha256(b"1").hexdigest(),16)
# flag = "TRX{this_is_a_fake_flag}"


r1, s1 = get_enc()
r2, s2 = get_enc()

M = matrix(QQ, [
    [int(h * r2),   1, 0, 0, 0],
    [int(-s1 * r2), 0, 1, 0, 0],
    [int(-h * r1),  0, 0, 1, 0],
    [int(s2 * r1),  0, 0, 0, 1],
    [int(m),            0, 0, 0, 0]
])
# flag = "TRX{this_is_a_fake_flag}"
# d = bytes_to_long(flag.encode())
w = diagonal_matrix(QQ, [1] + [1 << 32] * 4, sparse=False)

M /= w
# print(M)
M = M.BKZ(proof=False)
M *= w
# h * k12 + d * R1 - s1 *k11 = 0
if M[0][0] == 0:
    k2 = M[0][1]
    k1 = M[0][2]
    d = (s1 * k1 - h * k2) * pow(r1, -1, m) % m
print(f"{d = }")
# d = 2067561151708850881280236955824520733206814622086596749181
# d = 22912958616593465904555680013014111704628853776149933128727
d = 12665778675426901009304775492452648006066412887856176947702
from string import *
length = 44

print(f"Length: {length}")
for c1 in ascii_lowercase:
    for c2 in ascii_lowercase:
        p1 = b"TRX{" + c1.encode() + c2.encode()
        p2 = b"}"
        unknown = length - len(p1) - len(p2)
        form = p1 + b"\x00" * unknown + p2


        F = PolynomialRing(ZZ, 'f', unknown)
        flag = list(F.gens())

        def coefficients(f):
            tmp = []
            for i in F.gens():
                tmp.append(f.coefficient(i))
            return tmp + [f.constant_coefficient()]

        def list_to_long(l):
            _ = 0
            for i in l:
                _ = _ * (1 << 8) + i
            return _

        f = list_to_long([i for i in p1] + [i + 109 for i in flag] + [i for i in p2]) - d
        M = block_matrix(ZZ, [
            [column_matrix(coefficients(f)), 1],
            [m, 0]
        ])
        # matrix_overview(M)
        w = diagonal_matrix([1] + [13] * (unknown) + [1], sparse=False)
        M /= w
        M = M.LLL(block_size = unknown, proof=False)
        M *= w
        # matrix_overview(M)
        for row in M:
            k = sign(row[-1])
            if row[0] == 0 and (row[-1] == 1 or row[-1] == -1):

                try:
                    flag = (bytes(x+109 for x in (k * row[1:unknown + 1]))).decode()
                    if flag.count("L") > 5 or any(c not in printable for c in flag):
                        pass
                    else:
                        print(c1 + c2 + flag)
                except:
                    pass
                    
# dlp_and_bkz_with_big_blocksize_together