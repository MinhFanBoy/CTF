from pwn import *
import string
from sage.all import *
# from pwnlib.tubes.process import process
# from pwnlib.tubes.remote import remote
from sage.modules.free_module_integer import IntegerLattice

def Babai_CVP(mat, target):
    M = IntegerLattice(mat, lll_reduce=True).reduced_basis
    G = M.gram_schmidt()[0]
    diff = target
    for i in reversed(range(G.nrows())):
        diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
    return target - diff
BLOCK_LEN = 128
CHARSET = string.ascii_uppercase + string.digits + string.ascii_lowercase
q1 = 57895665874783536962369408363969823887021530656373208299565102620846005563716018275834077962292286213472570266375824572745671541793458387390711613089471407869558363212866932533545785125988453002675479793768261480181947144057144941974626043243654731721303589851520175899531854692118423229594279209070187162279
p1 = 2 * q1 + 1
g1 = 2

username = b"Zayn"
passwd = b'NCIm6RJuC5dKHohq2J6vnd8mSsesHzDC77TH5PDoGLcXUEXSJQdPGWSBGa1Y03Vzyz0GNTkm6S8iO3grixHmY07sobuhXFwmuYfFDEjzkxgbs5aajuEe7ijpkHB3JF8T\x00'


mat = [[0 for _ in range(BLOCK_LEN + 1)] for __ in range(BLOCK_LEN + 1)]

CONN = process(['python3', 'chal.py'])

CONN.sendlineafter(b'>', b'1')
CONN.sendlineafter(b'username:', username)
CONN.sendlineafter(b'password:', passwd.hex().encode())

CONN.sendlineafter(b'>', b'1337')
CONN.sendlineafter(b'name:', username)
CONN.recvline()
user_token = eval(CONN.recvline().decode().strip())
print(user_token[0])

CONN.sendlineafter(b'>', b'1337')
CONN.sendlineafter(b'name:', b"admin")
CONN.recvline()
admin_token = eval(CONN.recvline().decode().strip())
print(admin_token[0])

bases = [pow(g1, x, p1) for x in user_token]

out = 0
for x, y in zip(user_token, passwd):
    out += x * y % q1

for i in range(BLOCK_LEN):
    mat[i][i] = 1
    mat[i][-1] = admin_token[i]
mat[-1][-1] = -q1
mat = Matrix(ZZ, mat)

for bit in range(11, 15):
    print(f'{bit = }')
    target = vector(ZZ, [2 ** bit for _ in range(BLOCK_LEN)] + [out])
    res = Babai_CVP(mat, target)
    msg = [x for x in res[:-1]]
    if all(x >= 0 for x in msg) and res[-1] < out:
        msg.append(out - res[-1])
        print(msg)
        break
if len(msg) != 129:
    print("Failed")
    exit()

admin_password = b""
while any([x > 0 for x in msg]):
    for i in range(len(msg)):
        if msg[i] >= 0x7f:
            admin_password += b"\x7f"
            msg[i] -= 0x7f
        elif msg[i] == 0:
            admin_password += b"\x00"
        elif msg[i] < 0x7f:
            admin_password += bytes([msg[i]])
            msg[i] = 0

if len(admin_password) % 129 != 0:
    admin_password += b"\x00" * (129 - len(admin_password) % 129)
print(admin_password)
blocks = [admin_password[i:i + 129] for i in range(0, len(admin_password), 129)]  
blocks = b''.join(list(set(blocks)))

CONN.sendlineafter(b'>', b'1')
CONN.sendlineafter(b'username: ', b'Zyan')
CONN.sendlineafter(b'password: ', blocks.hex().encode())

CONN.sendlineafter(b'>', b'2')
CONN.sendlineafter(b'username: ', b'admin')
CONN.sendlineafter(b'password: ', admin_password.hex().encode())

CONN.interactive()
