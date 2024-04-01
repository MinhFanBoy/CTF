from z3 import *
from pwn import *

s = connect("betta.utctf.live", 7496)
words = BitVecs("v1 v2 v3 v4 v5", 5)

solver = Solver()

# for i in range(5):
#     solver.add(words[i] >= 0)
#     solver.add(words[i] <= 255) 

print(s.recvline())
s.sendline(b"z" * 5)
tmp = int(s.recvline().strip().decode())
print(tmp)
solver.add(((ord("z") - words[0]) * (ord("z") - words[1]) * (ord("z") - words[2]) * (ord("z") - words[3]) * (ord("z") - words[4])) % 31 == tmp)


print(s.recvline())
s.sendline(b"zzzzy")
tmp = int(s.recvline().strip().decode())
print(tmp)
solver.add(((ord("z") - words[0]) * (ord("z") - words[1]) * (ord("z") - words[2]) * (ord("z") - words[3]) * (ord("y") - words[4])) % 31 == tmp)

print(s.recvline())
s.sendline(b"zzzyy")
tmp = int(s.recvline().strip().decode())
print(tmp)
solver.add(((ord("z") - words[0]) * (ord("z") - words[1]) * (ord("z") - words[2]) * (ord("y") - words[3]) * (ord("y") - words[4])) % 31 == tmp)

print(s.recvline())
s.sendline(b"zzyyy")
tmp = int(s.recvline().strip().decode())
print(tmp)
solver.add(((ord("z") - words[0]) * (ord("z") - words[1]) * (ord("y") - words[2]) * (ord("y") - words[3]) * (ord("y") - words[4])) % 31 == tmp)
print(s.recvline())

s.sendline(b"zyyyy")
tmp = int(s.recvline().strip().decode())
print(tmp)
solver.add(((ord("z") - words[0]) * (ord("z") - words[1]) * (ord("y") - words[2]) * (ord("y") - words[3]) * (ord("y") - words[4])) % 31 == tmp)

f = ""
if solver.check() == sat:
    m = solver.model()
    print(words)
    for v in words:
        print((m[v].as_long()))
else:
    print('fail')

print(f)
    