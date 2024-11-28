
from pwn import *
from tqdm import *
import os
from aeskeyschedule import reverse_key_schedule
from z3 import *
import aes

# context.log_level = "debug"
NORMAL_ROUNDS = 22
PREMIUM_ROUNDS = 24
PREMIUM_USER = b"premium"

# s = connect("challs.glacierctf.com", 13374)
s = process(["python3", "challenge.py"])

def Encrypt(msg):
    s.recvuntil(b'Enter option (1: Encrypt, 2: Premium Encrypt, 3: Guess Key): ')
    s.sendline("1")
    s.sendline(msg)
    s.recvuntil(b"Ciphertext: ")
    tmp = s.recvline().strip().decode()
    return bytes.fromhex(tmp)

def Pre_Encrypt(ct, msg):
    s.recvuntil(b'Enter option (1: Encrypt, 2: Premium Encrypt, 3: Guess Key): ')
    s.sendline("2")
    s.recvuntil(b"Enter ciphertext: ")
    s.sendline(ct.hex())
    s.recvuntil(b"Enter plaintext: ")
    s.sendline(msg)
    s.recvuntil(b"Ciphertext: ")
    tmp = s.recvline().strip().decode()
    return bytes.fromhex(tmp)

def haft_encrypt(block):
    block = aes.bytes2matrix(block)
    aes.sub_bytes(block)
    aes.shift_rows(block)
    aes.mix_columns(block)
    return aes.matrix2bytes(block)

def haft_decrypt(block):
    block = aes.bytes2matrix(block)
    aes.inv_mix_columns(block)
    aes.inv_shift_rows(block)
    return aes.matrix2bytes(block)

enc_22 = Encrypt(aes.pad(PREMIUM_USER) + b"\x00" * 16)
enc_24 = Pre_Encrypt(enc_22[:16], aes.pad(PREMIUM_USER) + b"\x00" * 16)

enc_22_0 = enc_22[:16]
enc_22_1 = enc_22[16:32]
enc_22_2 = enc_22[32:48]

enc_24_0 = enc_24[:16]
enc_24_1 = enc_24[16:32]
enc_24_2 = enc_24[32:48]

enc_22_0 = haft_encrypt(enc_22_0)
enc_22_1 = haft_encrypt(enc_22_1)
enc_22_2 = haft_encrypt(enc_22_2)

enc_0 = xor(enc_22_0, enc_22_1)
enc_1 = xor(enc_22_0, enc_22_2)

dec_0 = haft_decrypt(xor(enc_24_1, enc_24_0))
dec_1 = haft_decrypt(xor(enc_24_2, enc_24_0))

key = []

for i in range(16):
    for x in range(256):
        
        y_0 = x ^ enc_0[i]
        y_1 = x ^ enc_1[i]
        if aes.s_box[y_0] ^ aes.s_box[x] == dec_0[i] and aes.s_box[y_1] ^ aes.s_box[x] == dec_1[i]:
            key.append(x)
            break
        
tmp = bytes(key)
tmp = xor(tmp, enc_22_0)
key = reverse_key_schedule(tmp, 3)
key = reverse_key_schedule(key, 10)
key = reverse_key_schedule(key, 10)

s.recvuntil(b'Enter option (1: Encrypt, 2: Premium Encrypt, 3: Guess Key): ')
s.sendline("3")
s.sendline(key.hex())
s.interactive()