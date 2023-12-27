from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random, time
import struct
from pwn import *

def aes_decrypt(key, ciphertext, iv):
    key = key.ljust(32)[:32]
    iv = iv.encode()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext)
    return padded_plaintext

s = connect("103.162.14.116", 16001)
txt = s.recv().decode()
txt = txt.split(": ")[1][:-1]
txt = txt.split(" ")
print(txt)

byte_list = txt
byte_list = byte_list[1:] if byte_list[0] == b'' else byte_list
plain_text = bytes([int(byte, 16) for byte in byte_list])

random.seed(int(time.time()/4))
iv = str(random.randint(10**(16-1), 10**16 - 1))

for num in range(2**20, 2**24):
    random.seed(num)
    num = (num >> 1 << 1) | 0
    key = num.to_bytes(3, byteorder='little')
    pt = aes_decrypt(key, plain_text, iv)
    if("KCSC{" in str(pt)): 
        print(pt)
        break