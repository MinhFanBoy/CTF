
from pwn import *
from tqdm import trange
from Crypto.Util.number import *
from sage.all import *

import os
from re import findall
from subprocess import check_output

def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

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

# s = connect("35.187.238.100", 5003)
s = process(["python3", "chall.py"])
# s.recvuntil(b'"')
# prefix = str(s.recvuntil(b'"')[:-1].decode().strip())
# s.recvuntil(b'"')
# difficulty = len(str(s.recvuntil(b'"')[:-1].decode().strip()))

# p = process(['python3', 'solver_proof.py', prefix, str(difficulty)])

# output = p.recvline()[:-1].decode().strip()
# p.close()

# s.sendline(output)

l = []
em = bytes_to_long(b'\x00\x01' + (b'\xFF' * 202) + b'\x00' + bytes.fromhex('3031300d060960864801650304020105000420') + b"\x00" * 32)

for _ in trange(30):
    s.recvuntil(b"> ")
    s.sendline(b"1")
    
    s.recvuntil(b"sig =")
    l.append(int(s.recvline()[:-1].decode().strip(), 16) ** 11 - em)
s.recvuntil(b"> ")
s.sendline(b"2")

s.recvuntil(b"sig =")
enc = int(s.recvline()[:-1].decode().strip(), 16)

A = diagonal_matrix([-l[0]] * 29)
B = matrix(l[1:])
w = 2 ** 32

M = block_matrix([
    [matrix([[w]]), B],
    [0, A]
])

for i in flatter(M):
    # print(i[0] % 2 ** 33, i[0])
    n_ = l[0] // (i[0] // 2 ** 32)
    # print(int(n_).bit_length())
    if int(n_).bit_length() == 2048:
        print(long_to_bytes(int(pow(enc, 11, n_))))