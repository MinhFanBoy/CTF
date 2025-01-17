
## Crypto

__**server.py**__

```py
import os
import random
import sys
from Crypto.Util.number import getRandomNBitInteger, bytes_to_long
from gmpy2 import is_prime
# from secret import FLAG
FLAG = b'FLAG{test_flag}'


def get_prime(nbits: int):
    if nbits < 2:
        raise ValueError("'nbits' must be larger than 1.")
    
    while True:
        num = getRandomNBitInteger(nbits) | 1
        if is_prime(num):
            return num


def pad(msg: bytes, nbytes: int):
    if nbytes < (len(msg) + 1):
        raise ValueError("'nbytes' must be larger than 'len(msg) + 1'.")

    return msg + b'\0' + os.urandom(nbytes - len(msg) - 1)


def main():
    for cnt in range(4096):
        nbits_0 = 1000 + random.randint(1, 256)
        nbits_1 = 612 + random.randint(1, 256)

        p, q, r = get_prime(nbits_0), get_prime(nbits_0), get_prime(nbits_0)
        n = p * q * r
        d = get_prime(nbits_1)
        e = pow(d, -1, (p - 1) * (q - 1) * (r - 1))

        m = bytes_to_long(pad(FLAG, (n.bit_length() - 1) // 8))
        c = pow(m, e, n)

        print(f'{n, e = }')
        print(f'{c = }')
        msg = input('Do you want to refresh [Y/N] > ')
        if msg != 'Y':
            break


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit()
    except KeyboardInterrupt:
        sys.exit()
```

Do số d nhỏ nên ta có thể hướng tới weiner attack như sau:

$e * d = 1 \pmod{phi} \to e * d = 1 + k * phi$
$e * d = 1 + k * (p - 1) * (q - 1) * (r - 1)$

đặt những phần chưa biết là s thì ta có:

$e * d = 1 + k * (n - s) \to k * n - d * e = 1 + k * s$

từ đó ta có thể đưa về ma trận như sau:

```py
M = [
    [n, S],
    [-e, 0]
]
```

Với S gần bằng $S = -p * q - p * r - q * r + q + p + r + 1 = 3 * n ^ {(2/3)}$

khi đó `[k, d] * M = [1 + k * s, k * S]` do `[1 + k * s, k * S]` là vector bé nên ta có thể tìm lại bằng LLL. Khi đó ta có thể dễ dàng tìm lại k, s và có thể tìm lại flag.

```py

import os

set_verbose(0)
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'linux'

import random
import sys
from Crypto.Util.number import *
from gmpy2 import iroot
from pwn import *


for _ in range(4096):
    i = process(["python", "server.py"])
    n, e = eval(i.recvline().strip().split(b' = ')[1])
    c = int(i.recvline().strip().split(b' = ')[1])

    S = 3 * (int(iroot(c, 3)[0]) ^ 2)

    M = matrix([
        [n, S], 
        [-e, 0]
    ]).LLL()

    k = M[0][1] // S
    s = (M[0][0] - 1) // k
    phi = n - s - 1

    d = inverse(e, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))
```