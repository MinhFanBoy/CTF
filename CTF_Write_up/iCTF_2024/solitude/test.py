
from pwn import *
from tqdm import tqdm
from string import *
from Crypto.Util.number import *

# s = connect("solitude.chal.imaginaryctf.org", 1337)

# s.recvline()
# s.recvuntil(b"got flag? ")
# s.sendline(b"2")

# ct_1 = bytes.fromhex(s.recvline().strip().decode())
# ct_2 = bytes.fromhex(s.recvline().strip().decode())

# ct_2 = bytes.fromhex("717b447c3d5306733234665d22670d6c59515e3c7905776d4e52287631181c361a")
# ct_1 = bytes.fromhex("7b0408537d64043974336a2a5f0c5b091a795c0476515e6e5159257137727c6549")

data = (ascii_letters + digits + "{}_").encode()

for i in data:
    tmp = []
    for k in range(128):
        tmp.append(bytes_to_long(xor(i, k)))
    print(f"{chr(i)}:", tmp[-1])
