
## TRX CTF 2025/ Crypto

+ [offical wu TRX CTF 2025](https://github.com/TheRomanXpl0it/TRX-CTF-2025)
+ [Sarkoxed wu](https://github.com/Sarkoxed/ctf-writeups/tree/master/trx-2025)
+ [magicfrank00 wu](https://magicfrank00.github.io/writeups/writeups/trxctf/trxctf-crypto/#lepton2---writeup) và [lll-to-solve-linear-equations ](https://magicfrank00.github.io/writeups/posts/lll-to-solve-linear-equations/)

### 1. Lepton

```sage
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# CSIDH-512 prime
ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])

secret_vector = [randint(0, 1) for _ in range(len(ells))]

with open('flag.txt', 'r') as f:
    FLAG = f.read().strip()

def walk_isogeny(E, exponent_vector):
    P = E.random_point()
    o = P.order()
    order = prod(ells[i] for i in range(len(ells)) if exponent_vector[i] == 1)
    while o % order:
        P = E.random_point()
        o = P.order()
    P = o // order * P
    phi = E.isogeny(P, algorithm='factored')
    E = phi.codomain()
    return E, phi

while 1:
    E = E0
    phi = E.identity_morphism()
    random_vector = [randint(0, 1) for _ in range(len(ells))]
    E, _ = walk_isogeny(E, random_vector)
    E = E.montgomery_model()
    E.set_order(4 * prod(ells))
    print("[>] Intermidiate montgomery curve:", E.a2())
    print("[?] Send me your point on the curve")
    try:
        P = E([int(x) for x in input().split(",")])
        E, phi = walk_isogeny(E, secret_vector)
        E_final = E.montgomery_model()
        phi = E.isomorphism_to(E_final)*phi
        Q = phi(P)
        secret_key = sha256(str(Q.xy()[0]).encode()).digest()
        cipher = AES.new(secret_key, AES.MODE_ECB)
        print(cipher.encrypt(pad(FLAG.encode(), 16)).hex())
    except:
        print("[!] Invalid input")
        continue
```

Mình thấy rằng ở đây không có bất cứ diều kiện nào cho điểm `P` cả nên ta có thể gửi điểm `P = 0` khi đó `Q = phi(P) = phi(0) = 0`. Khi đó key = sha256(b"0") và ta dễ dàng có flag.

**_sol.py_**

```py
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

secret_key = sha256(b"0").digest()
cipher = AES.new(secret_key, AES.MODE_ECB)
print(cipher.decrypt(bytes.fromhex("3a641a40286eb1611870ca1a8609689793153b1f404037d202b36969d18e2bb61f6ff9e2fc12142c1a53e01f7f17dc17")))
```

### 2. factor.com

```py
import random
from Crypto.Util.number import getPrime, bytes_to_long
# flag = open('flag.txt', 'rb').read().strip()
flag = b'flag{this_is_a_fake_flag}'


def encrypt_flag():
    N = 1
    while N.bit_length() < 2048:
        N *= getPrime(random.randint(1,512))
    e = getPrime(random.randint(1024,2048))
    c = pow(bytes_to_long(flag), e, N)
    return N, e, c

try:
    while 1:
        N, e, c = encrypt_flag()
        print(f'N = {N}')
        print(f'e = {e}')
        print(f'c = {c}')
        new = input('Do you want to see another encryption? (yes/no): ')
        if new != 'yes':
            break
except Exception:
    pass
```

Khi kết nối tới server ta được nhiều cặp N, e, c trong đó N là tích của các số nguyên tố ngẫu nhiên từ 1 tới 512 bit và e là số nguyển tố trong khoảng (1024, 2048) bit. Ban đầu mình nghĩ có thể attack bằng boneh-durffe nhưng mà không phải mà nó đơn giản hơn nhiều. Do $N = n_1*n_2*...$ trong đó $n_1, n_2$ có thể rất nhỏ nên

$ m ^ e = c \pmod{N} \to m^e = c \pmod{n_1} \to m = c ^ {(e ^ {-1}) } \pmod{n_1}$

do có nhiều cặp như vậy nên ta có thể dùng crt để tìm lại flag.


**__sol.py__**

```py

import os
os.environ["TERM"] = "xterm-256color"
from math import log  # Hoặc from sage.all import math.log
from Crypto.Util.number import long_to_bytes
from pwn import *
# context.log_level = "DEBUG"

s = connect("factor.ctf.theromanxpl0.it", 7003)
# s = process(["python", "server.py"])
def get_enc():

    s.sendline("yes")
    lines = [s.recvline().decode().strip() for _ in range(3)]

    N = int(lines[0].split(" = ")[1])
    e = int(lines[1].split(" = ")[1])
    c = int(lines[2].split(" = ")[1])
    # s.close()
    factors = factor(N, limit = 1 << 20)
    # print(factors, "done !")
    if len(factors) == 1:
        return None
    ns = [(p, _) for p, _ in factors if p < 1 << 20]
    phi = prod([(p - 1) * (p ^ (_ - 1)) for p, _ in ns])
    n = prod([p ^ _ for p, _ in ns])
    d = inverse_mod(e, phi)
    # print(s.recv())
    return pow(c, d, n), n

ms, ns = [], []

while len(ms) < 50:
    tmp = get_enc()
    if tmp is None:
        continue
    m, n = tmp
    ms.append(m)
    ns.append(n)
    print(len(ms))

m = crt(ms, ns)
print(long_to_bytes(m))
# TRX{https://youtu.be/HKnUdvVXOuw?si=Fv7_UfGodgAhOWQN}
```

### 3. factordb.com

```py
from Crypto.Util.number import getPrime, bytes_to_long

p,q = getPrime(512), getPrime(512)
N = p*q
e = 65537

flag = b"TRX{??????????????????????}"
print(f"n = {N}")
print(f"e = {e}")
print(f"c = {pow(bytes_to_long(flag), e, N)}")
print(f"leak = {(0x1337 + p + q) ^ (0x1337 * p * q) & (p | 0x1337137)}")

# n = 48512240641840864698611285212880546891958282812678323164929695497979837667167371835079321738954614199887328209689700722900739026689495649897348371742808386272023319885638291436983171905959746612916786515990301081029893115996145232044829058978974408602308231813736063857659634459438506076453437963441215520733
# e = 65537
# c = 36547163254202175014719011914255607837474386170093760562818795855485895858656825454299902190817728613275689042837518944064285193789095094235166256812740012490802514031578972372211469389293445265540278842152695415520550436223647424764618861869589597420855316641231834238167223742740134122313062024294807514651
# leak = 20826963965199127684756501660137785826786703139116744934461978331055754408584988351275721454251225474905754748284336808278049322016982012115699743632649066
```

Phần quan trong trong bài này là `leak = {(0x1337 + p + q) ^ (0x1337 * p * q) & (p | 0x1337137)}`. Từ đó ta chỉ cần tìm kiếm lại p, q từ leak là dễ dàng có flag.

```py
from Crypto.Util.number import long_to_bytes

def find(p: str, q: str, i: int, n: int, leak: int):
    """
    Find p and q using the leak value, building the numbers bit by bit
    """
    if i > 512:  # Since we know p and q are 512-bit primes
        return
        
    p_ = int(p, 2)
    q_ = int(q, 2)
    
    # If we found valid factors, return them
    if p_ * q_ == n and p_ != 1 and q_ != 1:
        yield p_, q_
        return

    # Check if our current bits match the leak
    current_leak = (0x1337 + p_ + q_) ^ (0x1337 * p_ * q_) & (p_ | 0x1337137)
    # We only need to match the bits we've recovered so far
    mask = (1 << i)
    if (current_leak % mask) == (leak % mask) and (p_ * q_) % mask == n % mask:
        yield from find("0" + p, "0" + q, i + 1, n, leak)
        yield from find("0" + p, "1" + q, i + 1, n, leak)
        yield from find("1" + p, "0" + q, i + 1, n, leak)
        yield from find("1" + p, "1" + q, i + 1, n, leak)
n = 48512240641840864698611285212880546891958282812678323164929695497979837667167371835079321738954614199887328209689700722900739026689495649897348371742808386272023319885638291436983171905959746612916786515990301081029893115996145232044829058978974408602308231813736063857659634459438506076453437963441215520733
e = 65537
c = 36547163254202175014719011914255607837474386170093760562818795855485895858656825454299902190817728613275689042837518944064285193789095094235166256812740012490802514031578972372211469389293445265540278842152695415520550436223647424764618861869589597420855316641231834238167223742740134122313062024294807514651
leak = 20826963965199127684756501660137785826786703139116744934461978331055754408584988351275721454251225474905754748284336808278049322016982012115699743632649066
for i in find("1", "1", 1, n, leak):
    print(i)
p, q = (7035489142045828574752597537845070702081280952604701694849715987560062012789134699190474849118601736610457423751115697251323828282686416235385957186487411, 6895361454247676829228075850531328265117275439624742177383350062275971333828195643767216170008022492084495101783388323203249515849713869763042123612923503)
print(long_to_bytes(pow(c, pow(e, -1, (p-1)*(q-1)), p*q)))
```
### 4. Vectorial RSA

```py
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, getRandomInteger
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import numpy as np
import secrets
import hashlib
import random

FLAG = b"TRX{fake_flag_for_testing}"

# The great Roman modulus, the foundation of the Pact
p = getPrime(512)
q = getPrime(512)
n = p * q

# The public strengths of Generals Alicius and Bobius
eA = 27  # Alicius' power
eB = 35  # Bobius' power

# Secret keys, determined by fate
kA = getRandomInteger(100)
kB = kA + (-1 if random.randint(0, 1) else 1) * getRandomInteger(16)  # A slight, dangerous drift

# Alicius' secret calculations
e1 = [2, 3, 5, 7]
a1 = [69, 420, 1337, 9001]

# Bobius' secret calculations
e2 = [11, 13, 17, 19]
a2 = [72, 95, 237, 1001]

# Each general computes their part of the sacred key
c1 = sum([a * pow(kA, e, n) for a, e in zip(a1, e1)])  # Alicius' part
c2 = sum([a * pow(kB, e, n) for a, e in zip(a2, e2)])  # Bobius' part

# Encryption of each part using the other's public power
cA = pow(c1, eB, n)  # Alicius encrypts his secret for Bobius
cB = pow(c2, eA, n)  # Bobius encrypts his secret for Alicius

# The shared key, their fragile alliance
key = long_to_bytes(c1 + c2)
key = hashlib.sha256(key).digest()

# The exchange of trust
print(f"n = {n}")
print(f"eA = {eA}")
print(f"eB = {eB}")

# The encrypted secrets, waiting to be revealed
print(f"cA = {cA}")
print(f"cB = {cB}")

# The final encryption of Rome’s fate
iv = secrets.token_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(FLAG, 16))  
print("Here is the encrypted flag") 
print(f"iv = {iv.hex()}")
print(f"ciphertext = {ciphertext.hex()}")
```

```py
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(FLAG, 16))  
```
flag được mã nóa AES với key = c1 + c2 nên mục tiêu cần tìm lại c1, c2. Trong đó c1, c2 được tính như sau:

$c_1 = \sum_{i} a_{1,i} \cdot (k_A^{e_{1,i}} \mod n)$

$c_2 = \sum_{i} a_{2,i} \cdot (k_B^{e_{2,i}} \mod n)$

trong đó $k_B = k_A + r$ với `-2 ** 16 < r < 2 ** 16`
nên ta có thể viết

$c_1 = \sum_{i} a_{1,i} \cdot (k_A^{e_{1,i}} \mod n)$

$c_2 = \sum_{i} a_{2,i} \cdot ((k_A + r)^{e_{2,i}} \mod n)$

do `r` nhỏ nên ta có thể thực hiện bruteforce tìm r khi đó ta có thể sử dụng gcd để tìm lại $k_A$ và dễ dàng có được flag.


**__sol.py__**

```py
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, getRandomInteger
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import numpy as np
import secrets
import hashlib
import random
import os
import logging
from Crypto.Util.number import *
from tqdm import *
from sage.all import ZZ
from sage.all import Zmod

def _polynomial_hgcd(ring, a0, a1):
    assert a1.degree() < a0.degree()

    if a1.degree() <= a0.degree() / 2:
        return 1, 0, 0, 1

    m = a0.degree() // 2
    b0 = ring(a0.list()[m:])
    b1 = ring(a1.list()[m:])
    R00, R01, R10, R11 = _polynomial_hgcd(ring, b0, b1)
    d = R00 * a0 + R01 * a1
    e = R10 * a0 + R11 * a1
    if e.degree() < m:
        return R00, R01, R10, R11

    q, f = d.quo_rem(e)
    g0 = ring(e.list()[m // 2:])
    g1 = ring(f.list()[m // 2:])
    S00, S01, S10, S11 = _polynomial_hgcd(ring, g0, g1)
    return S01 * R00 + (S00 - q * S01) * R10, S01 * R01 + (S00 - q * S01) * R11, S11 * R00 + (S10 - q * S11) * R10, S11 * R01 + (S10 - q * S11) * R11


def fast_polynomial_gcd(a0, a1):
    """
    Uses a divide-and-conquer algorithm (HGCD) to compute the polynomial gcd.
    More information: Aho A. et al., "The Design and Analysis of Computer Algorithms" (Section 8.9)
    :param a0: the first polynomial
    :param a1: the second polynomial
    :return: the polynomial gcd
    """
    # TODO: implement extended variant of half GCD?
    assert a0.parent() == a1.parent()

    if a0.degree() == a1.degree():
        if a1 == 0:
            return a0
        a0, a1 = a1, a0 % a1
    elif a0.degree() < a1.degree():
        a0, a1 = a1, a0

    assert a0.degree() > a1.degree()
    ring = a0.parent()

    # Optimize recursive tail call.
    while True:
        logging.debug(f"deg(a0) = {a0.degree()}, deg(a1) = {a1.degree()}")
        _, r = a0.quo_rem(a1)
        if r == 0:
            return a1.monic()

        R00, R01, R10, R11 = _polynomial_hgcd(ring, a0, a1)
        b0 = R00 * a0 + R01 * a1
        b1 = R10 * a0 + R11 * a1
        if b1 == 0:
            return b0.monic()

        _, r = b0.quo_rem(b1)
        if r == 0:
            return b1.monic()

        a0 = b1
        a1 = r

e1 = [2, 3, 5, 7]
a1 = [69, 420, 1337, 9001]
e2 = [11, 13, 17, 19]
a2 = [72, 95, 237, 1001]

n = 64541532379927077000559872397264097749021972434205531336066931690486076647705413170185144940288988381635799051758671701941067093853968684354158364531117205968958931132385165913434941347527993061497902723498417954305499807823689010185704770834752024422286910181187814374841629893530443736915542004920807142781
eA = 27
eB = 35
cA = 44022142978819419618353382999440345073976186907275599632322745080012623162430540188907724797065065001963223657911160722898910372812863352246726924386760519377252296888984296509586878063185483891399718374344520697641288446229397649573154526152818589294889851730684140323675940582528405188097712041985150863134
cB = 36492103245285092647843551854942925373394229095706870054555977026553850101701906739652840770223455473246919620658344617649832752419944319254556813129428929352359138539967235739316345067424590082471814489355137379436050816028192665505036173068173821426333394966323037686047535779525861943853094214085274696593

iv = bytes.fromhex("922d9991e13113013496ada61eb3103c")
ciphertext = bytes.fromhex("5d2a59c1b5a5268baea17b095ad62310a0442eeeb2a6497f4074d70628f4ec5d51008a4ff12a6ea722e171656386f698ae530ac0824b0f5a77a93e2c063ac2f1")

F.<x> = PolynomialRing(Zmod(n))

# The public strengths of Generals Alicius and Bobius
eA = 27  # Alicius' power
eB = 35  # Bobius' power

c1_ = sum([a * x ** e for a, e in zip(a1, e1)])
for b in trange(54800 + 20, 54800 + 30):
    c2_ = sum([a * (x - b) ** e for a, e in zip(a2, e2)])
    k = (fast_polynomial_gcd(c1_ ** eB - cA, c2_ ** eA - cB))
    if k != 1:

        kA = int(-k.monic().constant_coefficient() % n)

        c1 = sum([a * pow(kA, e, n) for a, e in zip(a1, e1)])  
        c2 = sum([a * pow(kB, e, n) for a, e in zip(a2, e2)]) 
        cA = pow(c1, eB, n) 
        cB = pow(c2, eA, n)  

        key = long_to_bytes(c1 + c2)
        key = hashlib.sha256(key).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        flag = cipher.decrypt(ciphertext)  
        print(flag)
```

### 5. Brainrot

```py
from Crypto.Util.number import bytes_to_long as b2l
flag = open("flag.txt", "r").read().strip()
assert flag.startswith("TRX{") and flag.endswith("}")
# flag = flag[4:-1]
flag = "a" * 40
assert len(flag) == 40

def rot8000(s):
    news = ''
    for c in s:
        news += chr((ord(c) + 8000))
    return news

coeffs = [b2l(rot8000(flag[i:i+4]).encode('utf-16')) for i in range(0, len(flag), 4)]

def poly(x):
    return sum([c*x**i for i,c in enumerate(coeffs)]) % b2l(b'cant_give_you_everything')

points = [0xdeadbeef, 13371337, 0xcafebabe]

print([poly(p) % b2l(b'only_half!!!') for p in points])
# [25655763503777127809574173484, 8225698895190455994566939853, 10138657858525287519660632490]
```

Có flag được chia làm các đoạn bằng nhau rồi biến đổi qua hàm `b2l(rot8000(flag[i:i+4]).encode('utf-16'))` để tạo thành hệ số cho đa thức f(x) và ta có giá trị của f(x) tại 3 points bị mod cho `b2l(b'only_half!!!')`.

Với m1 = b2l(b'cant_give_you_everything'), m2 = b2l(b'only_half!!!') ta có 

$f(x) \pmod{m1} \pmod{m2} = out \to f(x) + k * {m2} = out \pmod{m1}$

$\sum_{i}{c_i * x ^ i} + k * m2 = out \pmod{m1}$

việc tính toán giá trị hàm c khá phức tạp ban đầu mình cũng không hiểu lắm nhưng sau khi tìm đọc wu thì mình có thể viết lại c như sau

$c_i = \sum_{j=0}^{3} \left( \left( (s_j + 0x40) \times 256 + 0x1f \right) \times (256^2)^{(3-j)} \right) + 0xfffe0000000000000000$

với flag được thay thế bằng dãy các ẩn [f0, f1, .., f39] tương đương với 40 bytes của flag thì ta có thể đươc được về thành các phương trình như sau:

$a_0 * f_0 + a_1 * f_1 + ... + a_39 * f_39 * k_i * m2 = out \mod{m1}$

do ta có 3 phương trình như trên nên có thể đưa về thành ma trận dạng như sau:
```py
    [M, 1],
    [bytes_to_long(b'cant_give_you_everything'),0]
```

với các hệ số là (f0, f1, ..., f39, k1, k2, k3, 1, d1, d2, d3) khi đó do các fs trong khoảng các chữ số có thể in được nên ta phải pad thêm để có thể tìm được flag đúng.

```py

from Crypto.Util.number import *
import s

out = [25655763503777127809574173484, 8225698895190455994566939853, 10138657858525287519660632490]
points = [0xdeadbeef, 13371337, 0xcafebabe]
coeffs = [var(f"c{i}") for i in range(0, 40, 4)]

def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)

F = PolynomialRing(ZZ, 'f', 43)
flags = F.gens()[:40]
flag = [f + 76 for f in flags]
k = F.gens()[-3:]

def rot_encode(s):
    return sum([((s[j] + 0x40)*256 + 0x1f)*(256**2)**(3-j) for j in range(4)])+ 0xfffe0000000000000000
coeffs = [rot_encode(flag[i: i + 4]) for i in range(0, len(flag), 4)]
def poly(x):
    return sum([c*x**i for i,c in enumerate(coeffs)])

f = []
for i, p in enumerate(points):
    f.append(poly(p) - out[i] - (k[i]) * bytes_to_long(b'only_half!!!'))

def coefficients(f):
    tmp = []
    for i in F.gens():
        tmp.append(f.coefficient(i))
    return tmp + [f.constant_coefficient()]

M = matrix([coefficients(i) for i in f]).T
M = block_matrix(ZZ, [
    [M, 1],
    [bytes_to_long(b'cant_give_you_everything'),0]
    ])

w = diagonal_matrix([1]*3 + [44]*40+ [(bytes_to_long(b'cant_give_you_everything')//bytes_to_long(b'only_half!!!')) >> 1]*3 + [1], sparse=False)
M /= w
M = M.BKZ(block_size=40, proof=False)
M *= w

for row in M:
    if row[-1] == 1 or row[-1] == -1:
        try:
            print(bytes(x+76 for x in (row[3:43])).decode())
        except:
            pass
        try:
            print(bytes(x+76 for x in (-row[3:43])).decode())
        except:
            pass
        # CurS37_aG4i##n_1nDiAneS#s_T0_7h3_Mo0n!!!

```

### 6. Baby DLP

```py
from hashlib import sha256
from binascii import crc32
import re
from Crypto.Util.number import bytes_to_long, long_to_bytes
from random import randint

# flag=open("flag.txt", "r").read().strip()
# assert re.match(r"TRX\{[a-z_]{39}\}", flag)
flag = "TRX{this_is_a_fake_flag}"
d = bytes_to_long(flag.encode())
E = EllipticCurve(GF(0x05ab035976b887b505bfcc20df74d9ab3d4a50cb87f5cede0d), [0x04ae328d15285fa70cf60749cf41cf14e1a316651fe8ce3b23, 0x03c7abc7899e550ba2eaeb5be64da31af90073a08c1d3e0215])

G = E(
    0x570f7cc8830e8cbfd1d8890fac962275f1553b11e4f3e2af7,
    0x9d18b5cee48c50824741c5f8fdf1cd8cbf9fc3dd200f2fe9
)

Q = d*G

m = 0x05ab035976b887b505bfcc20df74d9ab3d4a50cb87f5cede0d
def sign(msg, d):
    h = int(sha256(msg).hexdigest(),16)
    
    # double nonce = impossible to guess
    k1 = crc32(msg + str(randint(1, 2**32)).encode())
    k2 = crc32(msg + str(randint(1, 2**32)).encode())
    R = (k1+k2)*G
    s = (h*k2 + d*R[0])/k1

    return R, s

def verify(msg, R, s, Q):
    # I never remember how to do this properly
    return False

print("""Welcome to another super usefull signature service that can only sign messages!""")
print("Here is your public key:")
print(f"Q = ({Q[0]}, {Q[1]})")
print("I don't know what you will use it for, but as it's a public key, it's public!")

try:
    while True:
        print("""What do you want to do?
1 Sign a message
2 Verify a signature
* Exit""")
        choice = input("> ")
        if choice == "1":
            msg = input("Enter the message you want to sign: ").encode()
            R, s = sign(msg, d)
            print(f"Here is the signature:")
            print(f"R = ({R[0]}, {R[1]})")
            print(f"s = {s}")
        elif choice == "2":
            print("Sorry, I don't know how to do this.")
        else:
            print("Goodbye!")
            break
except Exception:
    pass

```

có `s = (h*k2 + d*R[0])/k1` trong đó R[0], s đã biết, k1, k2 là số 32 bit, còn d = flag mod m

+ $(h*k_2 + d*R) - k_1 * s = 0$

ta có hệ phương trình sau:
+ $(h*k_{21} + d*R_1) - k_{11} * s1 = 0$
+ $(h*k_{22} + d*R_2) - k_{12} * s2 = 0$

+ $d*R_1 =  k_{11} * s1 - h*k_{21}$
+ $d*R_2 =  k_{12} * s2 - h*k_{22}$

$\to (k_{11} * s1 - h*k_{21}) * R_2 = (k_{12} * s2 - h*k_{22}) * R_1$
$\to k_{11} * s1 * R_2 - h*k_{21}*R_2 - k_{12} * s2 * R_1 + h*k_{22} * R_1 = 0$

$
 \begin{pmatrix}
    k_{12} & k_{11} & k_{22} & k_{21} \\
 \end{pmatrix}
* 
 \begin{pmatrix}
   h * R_2   & 1 & 0 & 0 \\
   -s1 * R_2 & 0 & 1 & 0 \\
   -h * R_1  & 0 & 0 & 1 \\
   s2 * R_1  & 0 & 0 & 0 
 \end{pmatrix}
$

sử dụng lll là ta có thể dễ dàng tìm được k1, k2 và tìm lại được d. Do flag thỏa mãn 
```py
re.match(r"TRX\{[a-z_]{39}\}", flag)
```
nên flag có 44 ký tự và đã có 5 ký tự đã biết. Từ đó mình đưa flag thành dạng

```py
["T", "R", "X", "{", f0, f1, ..., f39, "}"]
```

ta cũng có f0, ..., f39 là những ký tự in thường và dấu "_" nên min(fs) = 95, max(fs) = 122

nên mỗi giá trị f mình sẽ cộng với 108 (trung bình của 95, 122) để các hệ số fs nhỏ nhất để ta có thể đưa về ma trận để lll. Để tỷ lệ tìm được flag cao hơn thì mình có brute thêm 2 ký tự của flag.

**__sol.py__**

```py
from hashlib import sha256
from binascii import crc32
import re
from Crypto.Util.number import bytes_to_long, long_to_bytes
from random import randint
import itertools
from sage.all import *

def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)

os.environ["TERM"] = "xterm-256color"

from pwn import *

m = 0x05ab035976b887b505bfcc20df74d9ab3d4a50cb87f5cede0d
# s = process(["sage", "chal.sage"])
s= connect("babydlp.ctf.theromanxpl0.it", 7002)

# context.log_level = "DEBUG"

def get_enc():
    s.sendline(b"1")
    s.sendline(b"1")
    s.recvuntil(b"Here is the signature:\n")
    # print(s.recvline())
    R = eval(s.recvline().decode().strip().split(" = ")[1])
    s_ = int(s.recvline().decode().strip().split(" = ")[1])
    return R[0], s_

h = int(sha256(b"1").hexdigest(),16)
# flag = "TRX{this_is_a_fake_flag}"


r1, s1 = get_enc()
r2, s2 = get_enc()

M = matrix(QQ, [
    [int(h * r2),   1, 0, 0, 0],
    [int(-s1 * r2), 0, 1, 0, 0],
    [int(-h * r1),  0, 0, 1, 0],
    [int(s2 * r1),  0, 0, 0, 1],
    [int(m),            0, 0, 0, 0]
])
# flag = "TRX{this_is_a_fake_flag}"
# d = bytes_to_long(flag.encode())
w = diagonal_matrix(QQ, [1] + [1 << 32] * 4, sparse=False)

M /= w
# print(M)
M = M.BKZ(proof=False)
M *= w
# h * k12 + d * R1 - s1 *k11 = 0
if M[0][0] == 0:
    k2 = M[0][1]
    k1 = M[0][2]
    d = (s1 * k1 - h * k2) * pow(r1, -1, m) % m
print(f"{d = }")
# d = 2067561151708850881280236955824520733206814622086596749181
# d = 22912958616593465904555680013014111704628853776149933128727
d = 12665778675426901009304775492452648006066412887856176947702
from string import *
length = 44

print(f"Length: {length}")
for c1 in ascii_lowercase:
    for c2 in ascii_lowercase:
        p1 = b"TRX{" + c1.encode() + c2.encode()
        p2 = b"}"
        unknown = length - len(p1) - len(p2)
        form = p1 + b"\x00" * unknown + p2


        F = PolynomialRing(ZZ, 'f', unknown)
        flag = list(F.gens())

        def coefficients(f):
            tmp = []
            for i in F.gens():
                tmp.append(f.coefficient(i))
            return tmp + [f.constant_coefficient()]

        def list_to_long(l):
            _ = 0
            for i in l:
                _ = _ * (1 << 8) + i
            return _

        f = list_to_long([i for i in p1] + [i + 109 for i in flag] + [i for i in p2]) - d
        M = block_matrix(ZZ, [
            [column_matrix(coefficients(f)), 1],
            [m, 0]
        ])
        # matrix_overview(M)
        w = diagonal_matrix([1] + [13] * (unknown) + [1], sparse=False)
        M /= w
        M = M.LLL(block_size = unknown, proof=False)
        M *= w
        # matrix_overview(M)
        for row in M:
            k = sign(row[-1])
            if row[0] == 0 and (row[-1] == 1 or row[-1] == -1):

                try:
                    flag = (bytes(x+109 for x in (k * row[1:unknown + 1]))).decode()
                    if flag.count("L") > 5 or any(c not in printable for c in flag):
                        pass
                    else:
                        print(c1 + c2 + flag)
                except:
                    pass
                    
# dlp_and_bkz_with_big_blocksize_together
```
