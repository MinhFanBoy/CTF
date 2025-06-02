
import os
os.environ["TERM"] = "linux"
from pwn import *
from Crypto.Util.number import *
from tqdm import *

while 1:
    s = connect("0.cloud.chals.io", 19964) 
    # s.interactive()

    s.sendline(b"i")

    s.recvuntil(b"pkey = ")
    n = int(s.recvline().strip())
    s.recvuntil(b"encrypted_flag = ")
    enc = eval(s.recvline().strip())

    s.sendline(b"p")
    s.sendline(b"3")

    l = []

    for i in trange(3):
        s.recvuntil(f"PLS[{i}] = ".format(i).encode())
        l.append(int(s.recvline().strip()))

    def agcd(N: list[int], R):
        n = N[0]

        M = block_matrix([
            [matrix([[R]]), column_matrix(N[1:]).T],
            [0, diagonal_matrix([-n]* (len(N) - 1)) ]
        ])

        q = int(abs(M.LLL()[0][0] // R))
        p = n // q
        return p

    nbit = 512
    p = (agcd([n] + l, 1 << (nbit >> 1)))
    q = n // p

    if not(p * q == n and is_prime(p) and is_prime(q)):
        continue
    print(f"{p = }")
    print(f"{q = }")

    a = pow(enc[1], pow(65537, -1, (p - 1) * (q - 1)), n)

    K = Zmod(n)
    R.<t> = PolynomialRing(K)
    F.<i> = K.extension(t^2 - a^2, 'a')
    ll = ((enc[0][0] + enc[0][1] * i))
    flag = (ll^(pow(65537, -1, (p - 1) * (q - 1))))

    print(long_to_bytes(int(str(flag).split("*i")[0])))
    exit()
