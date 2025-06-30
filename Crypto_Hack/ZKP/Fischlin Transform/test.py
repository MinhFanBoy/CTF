import random
from Crypto.Util.number import bytes_to_long
from params import p, q, g
from hashlib import sha512
import json
import os

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

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

def fischlin_proof(w0,w1,y0,y1,b = 0):
    if b:
        w_sim, w_b, y_sim, y_b = w0, w1, y0, y1
    else:
        w_sim, w_b, y_sim, y_b = w1, w0, y1, y0

    r_b = random.randint(0,q)
    a_b = pow(g,r_b,p)
    # Simulate transcript 1
    e_sim = random.randint(0,2**511-1)
    z_sim = random.randint(0,q)
    a_sim = (pow(pow(y_sim,e_sim,p),-1,p) *pow(g,z_sim,p)) % p
    
    # Normally you would sample for some `t` rounds, with `rho` parallel iterations
    # We simplify slightly for the purposes of this challenge. 
    # we just use `t` = 2**10, and `B` = 6, (and for this challenge we ignore parallel repititions/what happens if B is never hit)
    t = 2**10
    B = 6
    for e in range(t):
        # complete real transcript
        e_b = e^e_sim
        z_b = (r_b + e_b*w_b) % q

        # fix blinding
        if b:
            a0, a1, e0, e1, z0, z1 = a_sim, a_b, e_sim, e_b, z_sim, z_b
        else:
            a1, a0, e1, e0, z1, z0 = a_sim, a_b, e_sim, e_b, z_sim, z_b

        # if result of "random oracle" is small enough, we go with this transcript \o/
        res = Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1)
        if res < 2**(512-B):
            break  

    proof = {}
    proof["a0"] = a0
    proof["a1"] = a1
    proof["e"] = e
    proof["e0"] = e0
    proof["e1"] = e1
    proof["z0"] = z0
    proof["z1"] = z1

    return proof


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

def gen_round():
    w0 = random.randint(0,q)
    y0 = pow(g,w0,p)
    w1 = random.randint(0,q)
    y1 = pow(g,w1,p)
    assert (y0%p) >= 1 and (y1%p) >= 1
    assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1
    return w0, w1, y0, y1

for i in range(100):
    w0,w1,y0,y1 = gen_round()
    tmp = fischlin_proof(w0, w1, y0, y1, 1)
    if not fischlin_attack(w0, 0, y0, y1, 0, tmp):
        print(i)