from Crypto.Util.number import *
from sympy.ntheory.residue_ntheory import nthroot_mod
from tqdm import tqdm
p=14213355454944773291
q=61843562051620700386348551175371930486064978441159200765618339743764001033297
c=105002138722466946495936638656038214000043475751639025085255113965088749272461906892586616250264922348192496597986452786281151156436229574065193965422841
gift=9751789326354522940
"""
gift=pow(e+114514+p**k,0x10001,p)
"""
n=p**4*q
e = pow(gift, pow(0x10001, -1, p - 1), p) - 114514


lam  = (p - 1) * p ** 3 * (q - 1)
d = pow(e, -1, lam // e)
l = pow(2, lam // e, n)

for x in tqdm(range(0, e), desc = "Progress"):

    flag = long_to_bytes((pow(c, d, n) * pow(l, x, n)) % n)
    if b"hgame" in flag:
        print(flag)

