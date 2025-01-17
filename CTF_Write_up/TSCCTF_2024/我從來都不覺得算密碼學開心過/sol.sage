
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from tqdm import *

# load("https://raw.githubusercontent.com/MinhFanBoy/CTF/refs/heads/main/Important/solve_linear_mod.sage")
p = 42899
hs = [1934, 22627, 36616, 21343]
ciphertext = b'z\xa5\xa5\x1d\xe5\xd2I\xb1\x15\xec\x95\x8b^\xb6:r=\xe3h\x06-\xe9\x01\xda\xc03\xa4\xf6\xa8_\x8c\x12!MZP\x17O\xee\xa3\x0f\x05\x0b\xea7cnP'
flag = b"TSC{"
def check(r):
    re = []
    for i in range(4):
        h = flag[i]
        for j in range(5):
            h = (h + (j+1) * r[j]) % p
            r[j] = h
        re.append(h)
    return re
# rs = [var(f"r_{i}") for i in range(5)]

F = PolynomialRing(GF(p), ['r0', 'r1', 'r2', 'r3', 'r4'])
rs = F.gens()
r = list(rs)
M = []
N = []
for i in range(4):
    h = flag[i]
    for j in range(5):
        h = (h + (j+1) * r[j])
        r[j] = h
    M.append((h - hs[i]).coefficients()[:-1])
    N.append(-(h - hs[i]).coefficients()[-1])

M = matrix(M)
N = vector(N)

r = M.solve_right(N)
tmp = M.right_kernel_matrix()

for i in trange(p):
    _r = vector(GF(p), vector(r) + i * vector(tmp))
    _r = list(map(int, list(_r)))

    for i in range(4):
        h = flag[i]
        for j in range(5):
            h = (h + (j+1) * _r[j]) % p
            _r[j] = h
    _r = list(map(int, _r))
    key = 0
    for rr in _r:
        key += rr
        key *= 2**16
    key = int(key)
    key = pad(long_to_bytes(key), 16)
    aes = AES.new(key, AES.MODE_ECB)
    
    txt = aes.decrypt(ciphertext)
    if b"TSC{" in txt:
        print(txt)
        break