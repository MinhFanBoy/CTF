from pwn import *

while True:
    # io = remote("modnar.chal.wwctf.com", "1337")
    io = process(["python3", "chall.py"])
    io.recvuntil(b"my seed: ")
    seed = bytes.fromhex(io.recvline(False).decode())
    if seed[0] != 1:
        io.close()
        continue
    myseed = b"\x00\x80" + seed[:-1]
    t = xor(seed[-1], bytes([len(seed)]), bytes([len(seed) + 2]))
    myseed = myseed + t
    io.sendline(myseed.hex().encode())
    break

io.interactive()
