
# nc 172.31.2.2 9487
from pwn import *

s = connect("172.31.2.2", 9487)
# s = process(["python3", "chal.py"])

key1s = ["1FE01FE00EF10EF1", "01E001E001F101F1", "1FFE1FFE0EFE0EFE"]
key2s = ["E01FE01FF10EF10E", "E001E001F101F101", "FE1FFE1FFE0EFE0E"]

payload = b""

for i in range(100):
    s.sendline("1")
    s.sendline(bytes.fromhex(key2s[0]).hex())
    print(s.recvline())