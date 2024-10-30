from Crypto.Util.number import *
import hashlib
from secret import p,q,r
k1=getPrime(256)
k2=getPrime(256)
temp=p*2**256+q*k1+r*k2
hint=len(bin(temp)[2:])
flag='hgame{'+hashlib.sha256(str(p+q+r).encode()).hexdigest()+'}'
print(f'hint={hint}')
print(f'k1={k1}')
print(f'k2={k2}')
"""
83
k1=73715329877215340145951238343247156282165705396074786483256699817651255709671
k2=61361970662269869738270328523897765408443907198313632410068454223717824276837
"""