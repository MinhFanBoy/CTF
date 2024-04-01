
from pwn import *
import time
from Crypto.Cipher import AES

seed_root = int(time.time() * 1000) % (10 ** 6)
seed_root = 240933
print(seed_root)

def get_random_number():
    global seed 
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

def decrypt(message):
    key = b''
    for i in range(8):
        key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.decrypt(message)
    return ciphertext

# nc betta.utctf.live 7356

s = connect('betta.utctf.live', 7356)
s.recvuntil(b'What would you like to do (1 - get encrypted flag, 2 - encrypt a message)?\n')
s.sendline(b'1')
enc = s.recvline().split(b": ")[-1][:-1]

print(enc)

enc = b"6ed4899f616785ac5c26e6b35c7b649490dfa2ca7dafc13f56d92d9196c086c76d7ff70f491b25d3be5de2abadc745ab"
for i in range(1000000):
    seed = seed_root - i
    flag = (decrypt(bytes.fromhex(enc.decode())))
    if b'utflag' in flag:
        print(flag)
        break