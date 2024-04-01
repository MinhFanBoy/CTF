
from Crypto.Util.number import *
from pwn import *

s = connect("betta.utctf.live", 7496)


for i in range(3):

    print(s.recvline())
    s.sendline(b"a" * 5)
    tmp_1 = int(s.recvline().strip().decode())

    print(s.recvline())
    s.sendline(b"baaaa")
    tmp_2 = int(s.recvline().strip().decode())

    print(s.recvline())
    s.sendline(b"abaaa")
    tmp_3 = int(s.recvline().strip().decode())

    print(s.recvline())
    s.sendline(b"aabaa")
    tmp_4 = int(s.recvline().strip().decode())

    print(s.recvline())
    s.sendline(b"aaaba")
    tmp_5 = int(s.recvline().strip().decode())

    b_1 = tmp_1 * pow(tmp_1 - tmp_2, -1, 31) % 31
    b_2 = tmp_1 * pow(tmp_1 - tmp_3, -1, 31) % 31
    b_3 = tmp_1 * pow(tmp_1 - tmp_4, -1, 31) % 31
    b_4 = tmp_1 * pow(tmp_1 - tmp_5, -1, 31) % 31
    b_5 = tmp_1 * pow(-1 * b_1 * b_2 * b_3 * b_4, -1, 31) % 31
    
    s.sendline((str(chr(b_1 + ord("a")) + chr(b_2 + ord("a")) + chr(b_3 + ord("a")) + chr(b_4 + ord("a")) + chr(b_5 + ord("a")))).encode())
    print(str(chr(b_1 + ord("a")) + chr(b_2 + ord("a")) + chr(b_3 + ord("a")) + chr(b_4 + ord("a")) + chr(b_5 + ord("a"))))
    print(s.recvline())
    print(s.recvline())
print(s.recvline())
print(s.recvline())


