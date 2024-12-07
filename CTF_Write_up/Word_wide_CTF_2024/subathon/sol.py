
from Crypto.Util.number import *
from tqdm import trange
from aeskeyschedule import reverse_key_schedule
from aes import *
from pwn import *


# context.log_level = "debug"
while True:
    s = process(["python3", "chall.py"])
    s.recvuntil(b"flag_enc = ")
    c = eval(s.recvline().strip())
    # s.interactive()
    def c1():
        s.sendline(b"1")

    def c2():
        c1()
        s.sendline(b"2")
        s.sendlineafter(b">> ", b"00")
        s.recvuntil(b"You lose, the number was ")
        return long_to_bytes(int(s.recvline().strip().decode()))

    k = [set() for i in range(16)]

    # while True:
    for i in trange(10000):
        tmp = c2()
        for i, j in enumerate(tmp[:16]):
            if len(k[i]) < 255:
                k[i].add(j)
    possible_key = []

    for i in k:
        tmp = []
        i = list(i)
        for _ in range(256):
            if _ not in i:
                tmp.append(_)
        possible_key.append(tmp)
    print(possible_key)


    for i0 in possible_key[0]:
        for i1 in possible_key[1]:
            for i2 in possible_key[2]:
                for i3 in possible_key[3]:
                    for i4 in possible_key[4]:
                        for i5 in possible_key[5]:
                            for i6 in possible_key[6]:
                                for i7 in possible_key[7]:
                                    for i8 in possible_key[8]:
                                        for i9 in possible_key[9]:
                                            for i10 in possible_key[10]:
                                                for i11 in possible_key[11]:
                                                    for i12 in possible_key[12]:
                                                        for i13 in possible_key[13]:
                                                            for i14 in possible_key[14]:
                                                                for i15 in possible_key[15]:
                                                                    key = bytes([i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15])
                                                                    key = xor(key, bytes([234]) * 16)
                                                                    key = reverse_key_schedule(key, 10)
                                                                    cipher = AES(key)
                                                                    for _ in range(0, len(c), 16):
                                                                        flag = cipher.decrypt_block(c[_:_+16])
                                                                        print(flag)