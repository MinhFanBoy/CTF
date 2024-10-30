from Crypto.Util.number import *
import hashlib

l = 83
k1 = 73715329877215340145951238343247156282165705396074786483256699817651255709671
k2 = 61361970662269869738270328523897765408443907198313632410068454223717824276837

M = matrix([
    [k1, 1, 0, 0],
    [k2, 0, 1, 0],
    [2 ** 256, 0, 0, 1]
])
L = M.LLL()
# p*2**256+q*k1+r*k2

q = int(L[0][2])
r = int(L[0][3])
p = int(L[0][1])

flag='hgame{'+hashlib.sha256(str(p+q+r).encode()).hexdigest()+'}'
print(flag)