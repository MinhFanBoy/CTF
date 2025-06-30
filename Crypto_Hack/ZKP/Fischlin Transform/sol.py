
"""

w0, w1: random

y0 = g ^ w0
y1 = g ^ w1

r_b = random
a_b = g ^ r_b


e_sim, z_sim : radom
s_sim = y_sim ^ -e_sim * g ^ z_sim
B= 6
e: known

e_b = e ^ e_sim
z_b = (r_b + e_b*w_b)

w_sim, w_b, y_sim, y_b: known
a_sim, a_b, e_sim, e_b, z_sim, z_b: known

"""

# print("ok")
from Crypto.Util.number import *

from pwn import *
from json import *
from sympy import *
from tqdm import *
from hashlib import sha512

# kinda a random oracle
def Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1):
    ROstep = sha512(b'my')
    ROstep.update(str(a0).encode())
    ROstep.update(b'very')
    ROstep.update(str(a1).encode())
    ROstep.update(b'cool')
    ROstep.update(str(e).encode())
    ROstep.update(b'random')
    ROstep.update(str(e0).encode())
    ROstep.update(b'oracle')
    ROstep.update(str(e1).encode())
    ROstep.update(b'for')
    ROstep.update(str(z0).encode())
    ROstep.update(b'fischlin')
    ROstep.update(str(z1).encode())
    res = bytes_to_long(ROstep.digest())
    return res

def fischlin_attack(w0,w1,y0,y1,b, proof):

    a0 = proof["a0"] 
    a1 = proof["a1"] 
    e  = proof["e"]  
    e0 = proof["e0"] 
    e1 = proof["e1"] 
    z0 = proof["z0"] 
    z1 = proof["z1"]
    
    if b:
        w_sim, w_b, y_sim, y_b = w0, w1, y0, y1
    else:
        w_sim, w_b, y_sim, y_b = w1, w0, y1, y0

    if b:
        a_sim, a_b, e_sim, e_b, z_sim, z_b = a0, a1, e0, e1, z0, z1
    else:
        a_sim, a_b, e_sim, e_b, z_sim, z_b = a1, a0, e1, e0, z1, z0
    
    t = 2**10
    B = 6
    r_b = (z_b - e_b*w_b) % q
    
    for e_ in range(t):
        e_b = e_^e_sim
        z_ = (r_b + e_b*w_b) % q
        
        if b:
            a0, a1, e0, e1, z0, z1 = a_sim, a_b, e_sim, e_b, z_sim, z_
        else:
            a1, a0, e1, e0, z1, z0 = a_sim, a_b, e_sim, e_b, z_sim, z_

        res = Totally_a_random_oracle(a0,a1,e_,e0,e1,z0,z1)
        if res < 2**(512-B):
            return e == e_


p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2
lst = []
# s = process(["python3", "chal.py"])
s = connect("archive.cryptohack.org", 3583)
for round in trange(64):
    for i in trange(2 ** 4):

        s.recvuntil(b"y0 = ")
        y0 = int(s.recvline().decode().strip())
        s.recvuntil(b"y1 = ")
        y1 = int(s.recvline().decode().strip())

        s.sendlineafter(b"which witness do you want to see?", b"0")

        s.recvuntil(b"w0 = ")
        w0 = int(s.recvline().decode().strip())
        s.recvline()

        proof = eval(s.recvline())

        b = fischlin_attack(w0, 0, y0, y1, 0, proof)
        if b:
            s.sendlineafter(b"do you think you can guess my witness? (y,n)", b"n")
        else:
            s.recv()
            s.sendline(b"y")
            s.recv()
            s.sendline(b"1")
            s.recvline()

            break
    if i == 15:
        print("Failed")
        s.close()
        exit()
s.interactive()

"""
crypto{fishy_fischlin_www.youtube.com/watch?v=tL6dcQEY62s}
"""