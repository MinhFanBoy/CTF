
from pwn import *
from Crypto.Util.number import *
from string import *
from tqdm import *
s = connect("solitude.chal.imaginaryctf.org", 1337)

s.recvline()
s.recvuntil(b"got flag? ")

tmp = []
s.sendline(b"100000")
for i in tqdm(range(100000)):
    # print(s.recvline().strip().decode())
    tmp.append(bytes.fromhex(s.recvline().strip().decode()))
    
for i_ in range(33):
    k = [tmp[i][i_]for i in range(100000)]
    count_ = 0
    max_ = 0
    for i in (ascii_letters + digits + "{}_").encode():
        l = k.count(i)
        if l > count_:
            max_ = i
            count_ = l
            
    print(chr(max_), end="")

