
from pwn import *

s = process(["python", "chall.py"])
flag = b""

enc_flag = s.recvline().split(b" = ")[1].strip().decode()
enc_flag = bytes.fromhex(enc_flag)
enc_flag = [enc_flag[i:i+8] for i in range(0, len(enc_flag), 8)]

for i in enc_flag:
    s.sendline((flag + i).hex().encode())
    enc = s.recvline().split(b" = ")[1].strip().decode()
    enc = bytes.fromhex(enc)[-8:]
    flag += enc

print(flag)
