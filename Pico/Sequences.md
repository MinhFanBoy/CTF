
---

**_TASK:_**

I wrote this linear recurrence function, can you figure out how to make it run fast enough and get the flag?
Download the code here sequences.py
Note that even an efficient solution might take several seconds to run. If your solution is taking several minutes, then you may need to reconsider your approach.


**_FILE:_**

```py
import math
import hashlib
import sys
from tqdm import tqdm
import functools

ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfe7d7086e788af7922b")

# This will overflow the stack, it will need to be significantly optimized in order to get the answer :)
@functools.cache
def m_func(i):
    if i == 0: return 1
    if i == 1: return 2
    if i == 2: return 3
    if i == 3: return 4

    return 55692*m_func(i-4) - 9549*m_func(i-3) + 301*m_func(i-2) + 21*m_func(i-1)


# Decrypt the flag
def decrypt_flag(sol):
    sol = sol % (10**10000)
    sol = str(sol)
    sol_md5 = hashlib.md5(sol.encode()).hexdigest()

    if sol_md5 != VERIF_KEY:
        print("Incorrect solution")
        sys.exit(1)

    key = hashlib.sha256(sol.encode()).digest()
    flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()

    print(flag)

if __name__ == "__main__":
    sol = m_func(ITERS)
    decrypt_flag(sol)

```


---



```py
import hashlib
from sympy import *
from gmpy2 import mpz
import sys

sys.set_int_max_str_digits(0)

w = Matrix([[0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [55692, -9549, 301, 21]])
a = Matrix([[1, 0, 0, 0]])
b = Matrix([1, 2, 3, 4])
print(a, b)
P, D = w.diagonalize()

P_inv: Matrix = P ** -1

# a * P * D * P_inv * b
L = a * P
R = P_inv * b

f = 1 / gcd(tuple(R))
R = R * f
print(R)
print(L)
# D = Matrix([[-21, 0, 0, 0], [0, 12, 0, 0], [0, 0, 13, 0], [0, 0, 0, 17]])
i = int(2e7)
p = 10**10000

ip_1 = mpz(D[0, 0]) ** i
ip_2 = mpz(D[1, 1]) ** i
ip_3 = mpz(D[2, 2]) ** i
ip_4 = mpz(D[3, 3]) ** i

sub0 = L[0]*ip_1*R[0]
sub1 = L[1]*ip_2*R[1]
sub2 = L[2]*ip_3*R[2]
sub3 = L[3]*ip_4*R[3]
result = (sub0+sub1+sub2+sub3)

sol = mpz(result)//f







VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfe7d7086e788af7922b")

def decrypt_flag(sol):
    sol = sol % (10**10000)
    sol = str(sol)
    sol_md5 = hashlib.md5(sol.encode()).hexdigest()

    key = hashlib.sha256(sol.encode()).digest()
    flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)])

    print(flag)

decrypt_flag(sol)

```
