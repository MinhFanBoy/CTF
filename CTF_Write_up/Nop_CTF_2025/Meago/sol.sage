import os
os.environ["TERM"] = "linux"
import sys
from Crypto.Util.number import *
from pwn import *
from tqdm import *

nbit = 100
prec = 4 * nbit
R = RealField(prec)

def meago(x, y):
	y = (x * y**2) ** R(1/3)
	x = (x * y**2) ** R(1/3)
	return x, y

s = connect("0.cloud.chals.io", 22748)
# s = process(["sage", "meago.sage"])
# context.log_level = "debug"
s.send(b"m\n" * 5)
s.recvuntil(b"y0 = ")
y0 = R((s.recvline().strip().decode()))
k = 40000


s.sendline(b"m")
s.recvuntil(b"y = ")
y6 = R((s.recvline().strip().decode()))

s.sendline(b"m")
s.recvuntil(b"y = ")
y7 = R((s.recvline().strip().decode()))

x6 = R((y7 ** 3)/(y6 ** 2)) + R(10 ** (-120))

for i in trange(k - 1):
    x6, y6 = meago(x6, y6)

a, b, c, d = 1, 0, 0, 1

def cacl(a, b, c, d):
    a1 = 5/9 * a + 4/9 * c
    b1 = 5/9 * b + 4/9 * d
    c1 = 1/3 * a + 2/3 * c 
    d1 = 1/3 * b + 2/3 * d
    return a1, b1, c1, d1

for i in trange(4 + k):
    a, b, c, d = cacl(a, b, c, d)
    
x = (y6 * x6/(y0 ^ (d + b)))^(1 / (c + a))
print(x)
print(long_to_bytes(132319036933719016150144442420049870663057484788499311967590059162661889026143279739155894808721624960681249080614016202 * 10 ** 8))
# N0PS{fl04T_nUm8eR_RePre53nT_rEal_v4Lue_Wi7h_d3c1mal5}
