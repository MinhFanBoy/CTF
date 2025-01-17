from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from random import randrange

flag = open('flag.txt', 'r').read().strip().encode()

p = getPrime(16)
r = [randrange(1, p) for _ in range(5)]

print(f'p = {p}')

# You have 5 unknown random numbers
# But you can only get 4 hashes
# It is impossible to recover the flag, right?
for i in range(4):
    h = flag[i]
    for j in range(5):
        h = (h + (j+1) * r[j]) % p
        r[j] = h
    print(f"hash[{i}] = {h}")

key = 0
for rr in r:
    key += rr
    key *= 2**16

key = pad(long_to_bytes(key), 16)
aes = AES.new(key, AES.MODE_ECB)
ciphertext = aes.encrypt(pad(flag, AES.block_size))
print(f"ciphertext = {ciphertext}")