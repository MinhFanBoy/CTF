
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import random
from tqdm import tqdm

#!/usr/bin/env python3
# nc betta.utctf.live 2435

def get_random_number():
    global seed 
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

def encrypt(message):
    key = b''
    for i in range(8):
        key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return key.hex(), ciphertext.hex()

s = connect("betta.utctf.live", 2435)
for i in range(3):
    s.sendlineafter(b"What would you like to do (1 - guess the key, 2 - encrypt a message)?", b"2")

    print(s.recvline())
    print(s.recvline())
    s.sendline(b"I")
    print(s.recvuntil(b": "))
    enc = s.recvline().strip().decode()

    print(enc)

    for seed in tqdm(range(10 ** 6), desc="Find Seeds"):

        encrypt(b"random text to initalize key")
        key, enc_1 = encrypt(b"I")

        if enc_1 == enc:
            print(key)
            print(key, enc_1)
            print(type(enc_1))
            print(type(key))
            break

    print(s.recvline())
    s.sendline(b"1")
    print(s.recvline())
    print(s.recvline())
    s.sendline(key.encode())
    print(s.recvline())

print(s.recvline())