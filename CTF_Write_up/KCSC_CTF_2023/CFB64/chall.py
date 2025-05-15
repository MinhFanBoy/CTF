import time
import sys
import os
from Crypto.Cipher import AES
from flag import flag

key = os.urandom(16)
iv = os.urandom(16)

def encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=64)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

print(f'encrypted_flag = {encrypt(key, iv, flag).hex()}')

for _ in range(23):
    plaintext = bytes.fromhex(input("plaintext: "))
    print(f'ciphertext = {encrypt(key, iv, plaintext).hex()}')
