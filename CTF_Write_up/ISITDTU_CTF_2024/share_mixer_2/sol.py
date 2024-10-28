
from pwn import *
from Crypto.Util.number import long_to_bytes
from sage.all import *
import itertools
from tqdm import *

context.log_level = 'warn'

while True:
    while True:
        s = process(['python3', 'chall.py'])
        s.recvuntil(b"p = ")
        p = int(s.recvline()[:-1].decode().strip())

        if (p - 1) % 32 == 0:
            break
        s.close()

    xs = ' '.join(map(str, [pow(5, i * (p - 1) // 32, p) for i in range(32)]))
    s.recvuntil(b"Gib me the queries: ")
    s.sendline(xs.encode())
    s.recvuntil(b"shares = ")
    shares = eval(s.recvline()[:-1].decode().strip())

    try:
        print(long_to_bytes(sum(shares) * pow(32, -1, p) % p).decode())
        exit()
    except:
        pass