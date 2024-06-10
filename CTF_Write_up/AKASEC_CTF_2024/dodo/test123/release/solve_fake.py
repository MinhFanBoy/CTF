from pwn import *
from mt19937_crack import RandomSolver

# r = process(["python3", "chall_fake.py"])
r = connect("20.80.240.190", 4447)
# context.log_level = 'debug'
r.sendlineafter(b'? ', b'a'*25)
r.recvuntil(b'session:  ')
iv = r.recvline().strip()
print(f'{iv = }')

rndSolver = RandomSolver()

for i in range(624):
    r.recvuntil(b'Your new token is :  ')
    token = r.recvline().strip()
    print(f'{token = }')
    r.recvuntil(b'Enter your choice: ')
    r.sendline(b'1')
    r.recvuntil(b'id: ')
    token = bytes.fromhex(token.decode())
    token_fake = token[:48] + xor(token[48:64], xor(b'\x94\x8c\x08is_admin\x94\x88\x8c\x03k', b'\x94\x8c\x08is_admin\x94\x89\x8c\x03k')) + token[64:]
    r.sendline(iv+token_fake.hex().encode())
    r.recvuntil(b'The current key that was used to encrypt is ')
    key = r.recvline()[:-2]
    print(f'{key = }')
    key = (int(key,16))
    rndSolver.submit_getrandbits(key, 128)

rndSolver.getrandbits(128)
guess = rndSolver.getrandbits(128)
r.recvuntil(b'Enter your choice: ')
r.sendline(b'2')
r.sendlineafter(b"What is the key that I'm going to use next ?", hex(guess)[2:].zfill(32).encode())
r.interactive()



