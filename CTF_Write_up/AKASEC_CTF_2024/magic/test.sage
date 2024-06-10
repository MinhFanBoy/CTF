
from pwn import *
from tqdm import *
s = connect("20.80.240.190", 4455)

e = 65537

s.recvuntil(b"= ")
n = int(s.recvline().strip())

bit_flag = "1"
for i in tqdm(range(301, -1, -1)):

    s.sendlineafter(b": ", str(i).encode())
    s.recvuntil(b"= ")
    c = int(s.recvline().strip())

    tmp = int(bit_flag + "1", 2)

    if pow(tmp, e, n) == c:
        bit_flag += "1"
    else:
        bit_flag += "0"

flag = bytes.fromhex(hex(int(bit_flag, 2))[2:])
print(flag)