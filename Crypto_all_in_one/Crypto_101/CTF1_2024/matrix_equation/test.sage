import hashlib
from Crypto.Util.number import *
k1 = 73715329877215340145951238343247156282165705396074786483256699817651255709671
k2 = 61361970662269869738270328523897765408443907198313632410068454223717824276837

M = matrix([
    [k1, 1, 0, 0],
    [k2, 0, 1, 0],
    [2 ** 256, 0, 0, 1]
])

print(M.LLL())
#hgame{3633c16b1e439d8db5accc9f602f2e821a66e6d80a412e45eb3e1048dffbb0e2}