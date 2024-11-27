
Table_of_contens
=================

+ Trong giải này không làm được đây là bài viết để học hỏi sau khi đã tham khảo wu của 
    + [Solution của kurenaif](https://www.youtube.com/watch?v=KO-txEysFHU&t=5593s)
    + [Solution của y011d4](https://github.com/y011d4/my-ctf-challenges/tree/main/2024-SECCONCTF-Quals)

### 1. reiwa_rot13

---

**chal.py**

```py
from Crypto.Util.number import *
import codecs
import string
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from flag import flag

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q
e = 137

key = ''.join(random.sample(string.ascii_lowercase, 10))
rot13_key = codecs.encode(key, 'rot13')

key = key.encode()
rot13_key = rot13_key.encode()

print("n =", n)
print("e =", e)
print("c1 =", pow(bytes_to_long(key), e, n))
print("c2 =", pow(bytes_to_long(rot13_key), e, n))

key = hashlib.sha256(key).digest()
cipher = AES.new(key, AES.MODE_ECB)
print("encyprted_flag = ", cipher.encrypt(flag))
```

**output.txt**

```py
n = 105270965659728963158005445847489568338624133794432049687688451306125971661031124713900002127418051522303660944175125387034394970179832138699578691141567745433869339567075081508781037210053642143165403433797282755555668756795483577896703080883972479419729546081868838801222887486792028810888791562604036658927
e = 137
c1 = 16725879353360743225730316963034204726319861040005120594887234855326369831320755783193769090051590949825166249781272646922803585636193915974651774390260491016720214140633640783231543045598365485211028668510203305809438787364463227009966174262553328694926283315238194084123468757122106412580182773221207234679
c2 = 54707765286024193032187360617061494734604811486186903189763791054142827180860557148652470696909890077875431762633703093692649645204708548602818564932535214931099060428833400560189627416590019522535730804324469881327808667775412214400027813470331712844449900828912439270590227229668374597433444897899112329233
encyprted_flag =  b"\xdb'\x0bL\x0f\xca\x16\xf5\x17>\xad\xfc\xe2\x10$(DVsDS~\xd3v\xe2\x86T\xb1{xL\xe53s\x90\x14\xfd\xe7\xdb\xddf\x1fx\xa3\xfc3\xcb\xb5~\x01\x9c\x91w\xa6\x03\x80&\xdb\x19xu\xedh\xe4"
```

---

#### 1. Tổng quan

+ Ta có `key = ''.join(random.sample(string.ascii_lowercase, 10))` key là 10 chữ cái in thường ngẫu nhiên và `rot13_key = codecs.encode(key, 'rot13')` là key trên những đã được mã hóa rot_13.
+ Còn flag được mã hóa bằng key lúc chưa được mã hóa rot_13.

```
key = hashlib.sha256(key).digest()
cipher = AES.new(key, AES.MODE_ECB)
```

+ ta có ${key} ^ e = c1 \pmod{n}$ và ${key_rot_13} ^ e = c2 \pmod{n}$ và mục tiêu của ta là phải tìm lại được key ban đầu là sẽ dễ dàng có flag.

#### 2. Solution

+ Hàm `encode(key, 'rot13')` là hàm mã hóa rot_13 trong bảng chữ cái in thường (có tất cả 26 chữ cái) nên:
    + Nếu `key < 13` thì ta có kết quả là `key + 13`
    + Nếu `key >= 13` thì ta có `key + 13 mod (26)` mà $13 = -13 \pmod{26}$ nên ta có thể viết với `key > 13` thì kết quả là `key - 13`
+ Do đây đang là chữ cái nên key = `bytes_to_long(key.encode())` khi đó ta có thể viết key là

${key} = \sum_{i = 0}^{len(key)}{key[i] * (256 ^ i)}$

${key_rot13} = \sum_{i = 0}^{len(key)}{(key[i] {+-} 13) * (256 ^ i)}$

mà key chỉ có 10 ký tự nên ta có thể brute để tìm dấu của nó.
khi đó ta có thể tìm được mối quan hệ của `key` và `key_rot13` và dùng `gcd` để tìm lại key. Khi có key rồi thì dễ dàng có `flag`.

#### 3. Code

```py

import logging 
import sys
from Crypto.Util.number import *
from tqdm import trange
import hashlib
from Crypto.Cipher import AES

sys.setrecursionlimit(500000)

def HGCD(a, b):
    if 2 * b.degree() <= a.degree() or a.degree() == 1:
        return 1, 0, 0, 1
    m = a.degree() // 2
    a_top, a_bot = a.quo_rem(x^m)
    b_top, b_bot = b.quo_rem(x^m)
    R00, R01, R10, R11 = HGCD(a_top, b_top)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    q, e = c.quo_rem(d)
    d_top, d_bot = d.quo_rem(x^(m // 2))
    e_top, e_bot = e.quo_rem(x^(m // 2))
    S00, S01, S10, S11 = HGCD(d_top, e_top)
    RET00 = S01 * R00 + (S00 - q * S01) * R10
    RET01 = S01 * R01 + (S00 - q * S01) * R11
    RET10 = S11 * R00 + (S10 - q * S11) * R10
    RET11 = S11 * R01 + (S10 - q * S11) * R11
    return RET00, RET01, RET10, RET11
    
def GCD(a, b):

    q, r = a.quo_rem(b)
    if r == 0:
        return b
    R00, R01, R10, R11 = HGCD(a, b)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    if d == 0:
        return c.monic()
    q, r = c.quo_rem(d)
    if r == 0:
        return d
    return GCD(d, r)

n = 105270965659728963158005445847489568338624133794432049687688451306125971661031124713900002127418051522303660944175125387034394970179832138699578691141567745433869339567075081508781037210053642143165403433797282755555668756795483577896703080883972479419729546081868838801222887486792028810888791562604036658927
e = 137
c1 = 16725879353360743225730316963034204726319861040005120594887234855326369831320755783193769090051590949825166249781272646922803585636193915974651774390260491016720214140633640783231543045598365485211028668510203305809438787364463227009966174262553328694926283315238194084123468757122106412580182773221207234679
c2 = 54707765286024193032187360617061494734604811486186903189763791054142827180860557148652470696909890077875431762633703093692649645204708548602818564932535214931099060428833400560189627416590019522535730804324469881327808667775412214400027813470331712844449900828912439270590227229668374597433444897899112329233
encyprted_flag =  b"\xdb'\x0bL\x0f\xca\x16\xf5\x17>\xad\xfc\xe2\x10$(DVsDS~\xd3v\xe2\x86T\xb1{xL\xe53s\x90\x14\xfd\xe7\xdb\xddf\x1fx\xa3\xfc3\xcb\xb5~\x01\x9c\x91w\xa6\x03\x80&\xdb\x19xu\xedh\xe4"

cacl = lambda x: sum(i * (256 ** j) for j, i in enumerate(x[::-1]))

R.<x> = PolynomialRing(Zmod(n))


for i in trange(0, 1 << 10):
    diff = list(map(int, bin(i)[2:].zfill(10)))
    diff = [13 if i == 1 else -13 for i in diff]
    w = cacl(diff)
    g = (x) ^ e - c1
    PR.<y> = R.quotient(g)
    h = (y + w)^e - c2
    f = h.lift()
    key = long_to_bytes(int(-GCD(g, f).change_ring(Zmod(n)).monic().coefficients()[0] % n))
    
    if len(key) == 10:
        key = hashlib.sha256(key).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        print(cipher.decrypt(encyprted_flag))
```

### 2. Dual_summon

---

**chal.py**

```py
from Crypto.Cipher import AES
import secrets
import os
import signal

signal.alarm(300)

flag = os.getenv('flag', "SECCON{sample}")

keys = [secrets.token_bytes(16) for _ in range(2)]
nonce = secrets.token_bytes(16)

def summon(number, plaintext):
    assert len(plaintext) == 16
    aes = AES.new(key=keys[number-1], mode=AES.MODE_GCM, nonce=nonce)
    ct, tag = aes.encrypt_and_digest(plaintext)
    return ct, tag

# When you can exec dual_summon, you will win
def dual_summon(plaintext):
    assert len(plaintext) == 16
    aes1 = AES.new(key=keys[0], mode=AES.MODE_GCM, nonce=nonce)
    aes2 = AES.new(key=keys[1], mode=AES.MODE_GCM, nonce=nonce)
    ct1, tag1 = aes1.encrypt_and_digest(plaintext)
    ct2, tag2 = aes2.encrypt_and_digest(plaintext)
    # When using dual_summon you have to match tags
    assert tag1 == tag2

print("Welcome to summoning circle. Can you dual summon?")
for _ in range(10):
    mode = int(input("[1] summon, [2] dual summon >"))
    if mode == 1:
        number = int(input("summon number (1 or 2) >"))
        name   = bytes.fromhex(input("name of sacrifice (hex) >"))
        ct, tag = summon(number, name)
        print(f"monster name = [---filtered---]")
        print(f"tag(hex) = {tag.hex()}")

    if mode == 2:
        name   = bytes.fromhex(input("name of sacrifice (hex) >"))
        dual_summon(name)
        print("Wow! you could exec dual_summon! you are master of summoner!")
        print(flag)
```

---

#### 1. Tổng quan

+ Có mã hóa AES_GCM
```py
    aes1 = AES.new(key=keys[0], mode=AES.MODE_GCM, nonce=nonce)
    aes2 = AES.new(key=keys[1], mode=AES.MODE_GCM, nonce=nonce)
```
với key và nonce được khởi tạo như sau:
```
keys = [secrets.token_bytes(16) for _ in range(2)]
nonce = secrets.token_bytes(16)
```
Có hai hàm chính như sau:
+ `summon(number, plaintext)`: mã hóa 16 bytes plaintext và cho chúng ta chọn 1 trong hai key cùng với nonce đã được khởi tạo. Mặc dù hàm có trả cho ta cả `ct` và `tag` nhưng server chỉ gửi mỗi `tag` lại.
+ `dual_summon(plaintext)`: mã hóa 16 bytes plaintext bằng hai key và 1 nonce được khởi tạo và trả lại kết quả là `tag1 == tag2`.


#### 2. Solution

Có quá trình mà hóa của AES_GCM như sau:

![](https://meowmeowxw.gitlab.io/ctf/utctf-2020-crypto/aes-gcm.png)

Do ảnh ở trên là quá trình mã hóa 2 block nhưng thực tế mình mã hóa 1 block nên có thể viết lại như sau:

`((A * H + C) * H + L) * H + S = Tag ` Với `C_i = P_i xor E_i`

Với:
```
K = AES key.
P = plaintext.
C = ciphertext.
A = associated data.
H = AES(K,$0 ^ {​128}$​​).
J​0​​ = Nonce ∣∣ + 00 * 31 + 0​​1.
S = AES(K,J​0​​).
GHASH(X) = X∈GF(2128) $x ^ {128} + x ^ 7 + x ^ 2 + x + 1$.
L = L​a​ ​+ L​c​​
M = message
E_i = E(key, i)
```
Mà ở đây không có sử dụng tới `associated data` nên `A = 0`

-> `C * H ^ 2 + L * H + S = Tag`

Giả sử ta có hai cặp `tag` và `M` tương ứng với cùng 1 nonce và key với nhau:

+ $C_1 * H ^ 2 + L * H + S = {Tag_1}$
+ $C_2 * H ^ 2 + L * H + S = {Tag_2}$

(vì có cùng key và nonce nên H = AES(K,$0 ^ {​128}$​​), S = AES(K,Nonce ∣∣ + 00 * 31 + 0​​1) bằng nhau)

+ Công hai đa thức ta có:
    + $(C_1 + C_2) * H ^ 2 = {Tag_1} + {Tag_2} \to (P_1 + E_1 + P_2 + E_1) * H ^ 2 = {Tag_1} + {Tag_2} \to (P_1 + P_2) * H ^ 2 = {Tag_1} + {Tag_2}$ 

Nên ta có $H = \sqrt{({Tag_1} + {Tag_2}) / ({M_1} + {M_2})}$

$S = {Tag} + C_2 * H ^ 2 + L * H $

Mà ta cần hai `tag` từ 2 key giống nhau nên ta cần:

+ $C_1 * H_1 ^ 2 + L * H_1 + S_1 = C_2 * H_2 ^ 2 + L * H_2 + S_2$

$\to (P + E_1) * H_1 ^ 2 + L * H_1 + S_1 = (P + E_2) * H_2 ^ 2 + L * H_2 + S_2$

$\to (P + E_1) * H_1 ^ 2 + L * H_1 + ((P_1 + E_1) * H_1 ^ 2 + L * H_1 + {Tag_1}) = (P + E_2) * H_2 ^ 2 + L * H_2 + ((P_2 + E_2) * H_2 ^ 2 + L * H_2 + {Tag_2})$

$\to (P ) * H_1 ^ 2 + {Tag_1} + P_1 * H_1 ^ 2 = (P) * H_2 ^ 2 + {Tag_2} + P_2 * H_2 ^ 2$

$\to P = ({Tag}_1 + {Tag}_2 + P_1 * H_1 ^ 2 + P_2 * H_2 ^ 2) / (H_1 ^ 2 + H_2 ^ 2)$

Ta mã hóa lạ P và gửi tới server là dễ dàng có flag.

#### 3. Code

```py

#!/usr/bin/env python

from pwn import *
from Crypto.Util.number import *
from sage.all import *

# context.log_level = "debug"

x = GF(2)["x"].gen()
gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)
h = gf2e["h"].gen()

def xor(b1,b2):
    return bytes([i^j for i,j in zip(b1,b2)])

# Converts an integer to a gf2e element, little endian.
def _to_gf2e(n):
    return gf2e([(n >> i) & 1 for i in range(127, -1, -1)])


# Converts a gf2e element to an integer, little endian.
def _from_gf2e(p):
    n = p.integer_representation()
    ans = 0
    for i in range(128):
        ans <<= 1
        ans |= ((n >> i) & 1)
    return int(ans)

def find_key(t1, t2, m1, m2):
    f = h ** 2 - (_to_gf2e(int.from_bytes(t1, byteorder="big")) + _to_gf2e(int.from_bytes(t2, byteorder="big"))) / (_to_gf2e(int.from_bytes(m1, byteorder="big")) + _to_gf2e(int.from_bytes(m2, byteorder="big")))
    H = f.roots()[0][0]
    return H

# s = connect("dualsummon.chal.seccon.jp", 18373)
s = process(["python3", "server.py"])

def get_encrypt(number, pt):
    s.sendlineafter(b"[1] summon, [2] dual summon >", b"1")
    s.recvuntil(b"summon number (1 or 2) >")
    s.sendline(number)
    s.recvuntil(b"name of sacrifice (hex) >")
    s.sendline(pt.hex())
    s.recvline()
    tag = bytes.fromhex(s.recvline().split(b"=")[1].strip().decode('utf-8'))
    return tag

m1 = b"\x00" * 16
m2 = b"\x00" * 15 + b"\x01"
m1 = b"a"*16
m2 = b"a"*15 + b"b"

t1 = get_encrypt(b"1", m1)
t2 = get_encrypt(b"1", m2)
t3 = get_encrypt(b"2", m1)
t4 = get_encrypt(b"2", m2)

H_1 = find_key(t1, t2, m1, m2)
H_2 = find_key(t3, t4, m1, m2)

L = _to_gf2e(((8 * 0) << 64) | (8 * 16))

M_1 = _to_gf2e(int.from_bytes(m1, byteorder="big"))
M_2 = _to_gf2e(int.from_bytes(m2, byteorder="big"))


Tag_1 = _to_gf2e(int.from_bytes(t1, byteorder="big"))
Tag_2 = _to_gf2e(int.from_bytes(t4, byteorder="big"))

m = _from_gf2e((M_1  * H_1 * H_1 + M_2 * H_2 * H_2 + Tag_1 + Tag_2) / (H_1 * H_1 + H_2 * H_2))


s.recvuntil(b">") 
s.sendline(b"2") # dual summon
s.recvuntil(b">") 
s.sendline(long_to_bytes(m).hex())
s.interactive()

```

### 3. Tidal_wave

---

**chall.py**

```py
import random
from Crypto.Util.number import getPrime
import secrets
from flag import flag

def get_Rrandom(R):
    return secrets.randbelow(int(R.order()))

def make_G(R, alphas):
    mat = []
    for i in range(k):
        row = []
        for j in range(n):
            row.append(alphas[j]^i)
        mat.append(row)
    mat = matrix(R, mat)
    return mat

def split_p(R, p, prime_bit_length, length):
    step = ceil(prime_bit_length/length)
    res = []
    while p > 0:
        res.append(ZZ(p % (2**step)))
        p >>= step
    return vector(R, res)

def make_random_vector(R, length):
    error_range = 2^1000
    res = []
    for _ in range(length):
        res.append(R(secrets.randbelow(int(error_range))))
    return vector(R, res)

def make_random_vector2(R, length):
    error_cnt = 28
    res = vector(R, length)
    error_pos = random.sample(range(length), error_cnt)
    for i in error_pos[:error_cnt//2]:
        res[i] = get_Rrandom(R)*p
    for i in error_pos[error_cnt//2:]:
        res[i] = get_Rrandom(R)*q
    return vector(R, res)

n, k = 36, 8
prime_bit_length = 512
p = getPrime(prime_bit_length)
q = getPrime(prime_bit_length)
N = p*q
R = Zmod(N)
alphas = vector(R, [get_Rrandom(R) for _ in range(n)])
G = make_G(R, alphas)
dets = [G.submatrix(0,i*k-i,8,8).det() for i in range(5)]
double_alphas = list(map(lambda x: x^2, alphas))
alpha_sum_rsa = R(sum(alphas))^65537

keyvec = vector(R, [get_Rrandom(R) for _ in range(k)])
pvec = split_p(R, p, prime_bit_length, k)

p_encoded = pvec*G + make_random_vector(R, n)
key_encoded = keyvec*G + make_random_vector2(R, n)

print(f"{N=}")
print(f"{dets=}")
print(f"{double_alphas=}")
print(f"{alpha_sum_rsa=}")
print(f"{p_encoded=}")
print(f"{key_encoded=}")

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key = hashlib.sha256(str(keyvec).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
encrypted_flag = cipher.encrypt(pad(flag, AES.block_size))
print(f"{encrypted_flag=}")

```

---

#### 1. Tổng quan

+ với N = p*q, `alphas = vector(R, [get_Rrandom(R) for _ in range(n)])` là một vector ngẫu nhiên

+ `get_Rrandom(R)`:

Hàm này trả về một số ngẫu nhiên trong khoảng 0 đến order() của đối số R.
Được sử dụng để tạo các số ngẫu nhiên trong Zmod(N).


+ `make_G(R, alphas)`:

Hàm này tạo ra ma trận G từ danh sách alphas.
G là một ma trận kích thước k x n, mỗi hàng là một vector [alphas[j]^i for j in range(n)].
Ma trận G này sẽ được sử dụng để mã hóa các vector.


+ `split_p(R, p, prime_bit_length, length)`:

Hàm này chia số nguyên lớn p thành một vector của các số nguyên nhỏ hơn.
Mỗi số nguyên nhỏ có prime_bit_length/length bit.
Điều này có thể giúp xử lý p dễ dàng hơn.


+ `make_random_vector(R, length)`:

Hàm này tạo ra một vector ngẫu nhiên trong Zmod(N) với độ dài length.
Các phần tử trong vector có giá trị tối đa là 2^1000.


+ `make_random_vector2(R, length)`:

Hàm này tạo ra một vector ngẫu nhiên trong Zmod(N) với độ dài length.
Có chừng 28 phần tử sai lệch, trong đó một nửa là bội số của p và một nửa là bội số của q.
Cấu trúc lỗi này có thể được sử dụng để phục hồi keyvec.

#### 2. Solution

```
G = [1      1         1  ...  1
    alpha₁    alpha₁²    ...  alpha₁ⁿ⁻¹
    alpha₂    alpha₂²    ...  alpha₂ⁿ⁻¹
    alpha₃    alpha₃²    ...  alpha₃ⁿ⁻¹
    ...        ...       ...  ...
    alpha_n   alpha_n²   ...  alpha_nⁿ⁻¹]
```
G là chuyển vị của ma trận Vandermonde có dạng như sau:


![](https://wikimedia.org/api/rest_v1/media/math/render/svg/893fa42fe4c670dfcc36f2d5e0d2c5a130eb40b8)


Điều đó khiến cho các định thức con của ma trận có dạng như sau:

+ ![](https://wikimedia.org/api/rest_v1/media/math/render/svg/19520a85e5d403fcfe3a6e594cebdbcf0975c544)

nê mình dễ dàng có được 7 phương trình gồm tích của các hệ số alpha. Do đã biết cả alpha bình phương nên ta hoàn toàn có thể sử dụng groebner_basis để tìm lại mối liên quan giữa các phương trình. Nhưng do còn đang thiếu ẩn nên ta chỉ tìm được các phương trình như sau:

```

x0 = a0 * x35
x1 = a1 * x35
x2 = a2 * x35

...


```

nhưng mà ta cũng có $(\sum_{i = 0}^{35}{x_i}) ^ {65537} = c$

nên $(\sum_{i = 0}^{35}{a_i * x_{35}}) ^ {65537} = (\sum_{i = 0}^{35}{a_i}) ^ {65537} * (x_{35}) ^ {65537} = (\sum_{i = 0}^{35}{a_i * x_{35}}) ^ {65537} * (x_{35} ^ 2) ^ {65537 // 2} * x_{35} = c$

do đã biết $x_{35} ^ 2$ nên ta có thể dễ dàng tính $x_{35}$, khi có $x_{35}$ thì ta dễ dàng có thể tìm lại các hệ số khác và tìm lại `alphas`.

Khi đã có alphas ta có thể tìm lại được `G` và sử dụng cvp để tìm lại một phần của p. Phàn còn lại có thể dễ dàng khôi phục bằng copper smith. Nhưng từ đây lại có một vấn đề khác, việc `key_encoded = keyvec*G + make_random_vector2(R, n)` được mã hóa như thế này khiến chúng ta không thể sử dụng được `cvp` như những bài trước. Vậy nên ở đây có một lỗi khác có thể khai thác được, đó là từ ma trận `G`.

https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction

Từ đấy mình có thể sử dụng bài toán tương tự là `GeneralizedReedSolomon` để giải quyết vấn đề này

#### 3. Code

```py


import random
from Crypto.Util.number import getPrime
import secrets
from tqdm import *
import lll_cvp
from functools import partial

import itertools

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), 1)
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []

def get_Rrandom(R):
    return secrets.randbelow(int(R.order()))

def make_G(R, alphas):
    mat = []
    for i in range(k):
        row = []
        for j in range(n):
            row.append(alphas[j]^i)
        mat.append(row)
    mat = matrix(R, mat)
    return mat

def split_p(R, p, prime_bit_length, length):
    step = ceil(prime_bit_length/length)
    res = []
    while p > 0:
        res.append(ZZ(p % (2**step)))
        p >>= step
    return vector(R, res)

def make_random_vector(R, length):
    error_range = 2^1000
    res = []
    for _ in range(length):
        res.append(R(secrets.randbelow(int(error_range))))
    return vector(R, res)

def make_random_vector2(R, length):
    error_cnt = 28
    res = vector(R, length)
    error_pos = random.sample(range(length), error_cnt)
    for i in error_pos[:error_cnt//2]:
        res[i] = get_Rrandom(R)*p
    for i in error_pos[error_cnt//2:]:
        res[i] = get_Rrandom(R)*q
    return vector(R, res)

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

f = open("output.txt", "r").readlines()

exec(f[0].strip())
exec(f[1].strip())
exec(f[2].strip())
exec(f[3].strip())
exec(f[4].strip())
exec(f[5].strip())
exec(f[6].strip())

N = N 
dets = dets 
double_alphas = double_alphas 
alpha_sum_rsa = alpha_sum_rsa 
p_encoded = p_encoded 
key_encoded = key_encoded 
error_range = 2^1000

n, k = 36, 8
R = Zmod(N)
F = PolynomialRing(R, [f"x{i}" for i in range(n)])
a = F.gens()

eqs = []

# for _ in trange(len(dets)):
#     mpoly = 1
#     tmp = a[_ * k - _: _ * k - _ + 8]

#     for i in range(k):
#         for j in range(i + 1, k):
#             mpoly *= (tmp[j] - tmp[i])
#     eqs.append(mpoly - R(dets[_]))

# for i in range(n):
#     eqs.append(a[i]**2 - R(double_alphas[i]))

# I = ideal(eqs)
# for i in I.groebner_basis():
#     print(i)
x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35 = a

w = [x35^2 + 106502442719364134109363347695169494665206224723879135571302919871347197162528368576046459190173738801441584598201613005115226654589967075243696168650875960165794300667505518784279616831677375105945353405248413775383770339596472437597634612950038247699176338503789901110765623621484205142672104326320567500816
, x0 + 101167463165697523840879155236135415366380424009464416331763855106184994633902302674087295255438751596774946284741606345729143993302112286520469294367507812315056318317781265297438013015868686890078715661635388273272226617417231986427962523043300715969264411559608335541462289882989793354071670690306513709519*x35
, x1 + 99816305691223099820353394198653556348673685338452752390709712662751963955018291035690933586495874204856425012304440226888304154089937984356244091799405992883850252885469253083907806945264024073842402938150768910238393582861876052386054944373525820386502846106714272089979496347781222903621586813884929103048*x35
, x2 + 153947320566716262616994979410188678739855205152591327118109633632831079874904201207623989372460852121565808503574990737588802732830815358621180239941162812988178974481362876713673930653580228231369894797024458703841541697777606681268859123289780674638214333073327446050895932236334966741881459108747047657435*x35
, x3 + 46659399542336213068024332009916486689825094553632368218365813655034953704942201817568253854157064388245504166146407757024451319917309905700295786319815343494402735002513497971306030063356005913518426592969826466597642398584629398113879014642476295408885955358537717006874886186944096839620200644124949825291*x35
, x4 + 126970603032089926662257849183463154484387763986070588029799255070985240096894601764925666146524415192970609755156080504028700396130098402820906150916788544913930045321434831936552231144039529166191052308107994701462252263094518074205134172570410670618493241431989836612834348355333485705234623653621004090049*x35
, x5 + 115508394461131230434265966592562541441480118295772381987049022892631341735888736661833392305223610800354559625226453090363759949922425321895315817754830944546620788649219943405574821438913838372662290595871423729706145914427966586662830609575957494588845127857943228556269621456937457333123492335951880013037*x35
, x6 + 67870041931046547730445280063184797432293459597028690348151237822083354786352372718957590792733098879508930013579571650980080382835547822977122585570672306974838997440709110285837607224398908231023960827174994279282071268896069837414435498169117619888694478279062781261004824001371533611247008055205968911459*x35
, x7 + 24398553029110400376703693451598141230041748203963027753191289213504745783444037069778370168024500310686272836682845403565282887410606919172609212330959626408043768540184381448069840251571366868345255466778720294684266113055942535915213333508027112834335738683622297868375118088422067594832286774454759842780*x35
, x8 + 12183761451807958449093612944496848250760712223750397113582125081291204485939043232204005669215344544643108606104447924194577560518784865889965010974193756466598588475400518141162335642468615029937654929450511699685166375085399707022464256552429379363061684027996282179882233590027951328871071648738057153701*x35
, x9 + 136283395600439917762324069683672425665271905977754374625741131631131381571945057306283556066272014713727191603504096877650248392527523580321540494478740292493256825563175718922625778845409304581876836565419832229110077250744626830556637936342385375785528837147746267716392030441762456697992109065716762836048*x35
, x10 + 137781388677775019803167341660564763023011205486809068857350068074131777057103291880618696729192482660745136169006276238378360485406598262470209434413326476713818755314175276254071566041358067268989295529524825374661553869756837620775030155881714487194281870539538723842048716551308069536173876572884159145482*x35
, x11 + 40022447050170079650297640809819914302194290183536692135687103304165226444531161643718985489156073578920524155702721149712467375112689527001518993125569865857136384760421621984994086354910186848710811862555146167565150643424318406707224495455455163366011675124228370243454814814469803353940490802919570540933*x35
, x12 + 120966263786521814150852565413458405789011054034289779641706161373543567247236870407999300175434137147788193262998857460937305136683936270467172487642423515043082666652377496706733346560628844290711324874759575204387651533624304598192790954517777168994380501673071117206104948457691832034877688369566421276268*x35
, x13 + 132961122689503792816396489813923533463353337544160342955427114699234305107032411860513530189794430586003314752218764427771069425571581230545144561573353395232729356644428585242872690321250270908179419633138107628038110692315823910364034651326849554101358397266150258020630476684609086641161097523429444286907*x35
, x14 + 159279176462545296578864033595509179410587926582287026147036009880694615378965287189294803671179500655532991093569299834618333127739161076476842432855898314443078790400762726706488087765691808008455184565423598329679576799087334897411704546553884360243457644895376211484147015788224880607598286047304839569871*x35
, x15 + 34807169980868726384973662496932373459025513195701386614403820227055411517151000671411095813528684636234527525283189460384821010483192915224093633698162756287836721166194219308354937612260372915060985133526124654525090877132302325000590360591346630570436251943255560968791457002066610857941700860046755639841*x35
, x16 + 135941728344653619168554218682054406788447973928907913298435906533443461858841620969183570549875126730938204966328461536238552896087878757176993616217297870244396790709012585329415344955165710927389110978839472844878749793985217744019769063812491347152364172608900369021723053049591937966849976280148886515157*x35
, x17 + 23022450653512113672763575288134457870864337520509152439208629951172177829969804360160254743445480528009804392118930762486706506600390483535195366718547398013829547169302737942011656985108244803051511900748651994722440069444977444110923567969194631813096457367853783284683870106054183475113035069580343560954*x35
, x18 + 109497499101385973960478956409212368393890321828294047706935450802449135737197006780594678597172915930516852803812780034628215320105893463771426189888943007254092358029997308546512896695266765204467861856963664286070650239788165819844446851134019428832918009318674952192115339660095607238715708771569399215838*x35
, x19 + 17649284393596838928927278310827176242509215110644386352481639332148633331772347689769852584315177880225227383888817435241415960568928130205087247521716901944147133976065732030250285301530147525056521201283295287128161451737388744898326241164907663755093951709088748838147576345829767478029082772419477723781*x35
, x20 + 130320272208550606000162249968811128701555128924925284832865563977090537272377093511217362483670891200613682176584857884689416065597281384854023729012295638738457294788171665924424141182979840209635991697860390277375640005807874613276565064742340398294618866435972420736846325480518954404493956123066884546272*x35
, x21 + 39101123999524075418371960194638271743945247842543623447599791358827143617840360905870500131725384519168233959470166267524033392762391083565838093889016408920456075067991209702927247019512513546515882432963122922769961496979348926444647296430777023918416291618593981106143559529205722916065184006818114143303*x35
, x22 + 48199732797571512474381843081410642427988233761233604916182072056585349447595749822299392864946822100642530711165709824205455392635027910363323358595484450915165289735674539072077220503789629362663719394601149021693838846631179978798887605892673834170072894903988402483773925234470242983441802495439924061332*x35
, x23 + 16665194243526064720137259674313963879120151991839610727414651302673500649858162153221648993343327185421487162449640330009856176853413856967461418999586870355231828840663851832997872589063688637889059215891619469462813800531907621060562700092290619760698514174163532494467026612760958067638436267540689263990*x35
, x24 + 52249003167873639497505287660809803154813283271579860201446532098065066334523207283836965218945451995068094803937471963191889335735593020062213461560738874871773486303345263057963545007413379053318379626696793620196796750586781773365596492318231557324461271284760629230781162323519744938214940310805490247065*x35
, x25 + 137793160780300611942398684838285079654158845540611353325901027340927100276010203663263055411134425794690868511147162746881189528295180032035069377375788665843850910615210644353422755227661626965661647124191627395094177496527126279657106471221142126683650879012630348182572396862913331654771241074468185614681*x35
, x26 + 41913542176762718356180572385723273028037257322465353038962822254259818024858416922770774760302862807725687896509935715213699378001675000630014920308214991620727341310184703667882069399318120877751389776468482619772868513482577491507627658526865403548692237621332762006400329001675838717069103279036559905098*x35
, x27 + 62499604425532139090540080719016290220708831784300706804453856969496109915462948489408851823031600962920651951049072871907217297846922891646886703161773184243984497097235420859868105460655674556771640108653411674397899745776925124142023521308515481427652856182154838392133714134935964637738869311200221013778*x35
, x28 + 64812852826577729459296495819920124605061016861309162575638214007028018131310793406676855463378160896786059539813356624395559458465603826738084948197251067308637653681669233965783727763766170746923609307367066177475560251316993122498159586658613976593096131912069745844256544973066144266318756517658323906500*x35
, x29 + 13930505220178812499334344928142906427788623106541586177912703458685079135242433252765674734277964006514138316612684583911134366015459508476011088285309323729658492226054360270637134300046620962139384065834504865707162953990027570442968896379626667891650442155917667277386210140165597397650993677709524354325*x35
, x30 + 163789129881499257485091385047599447721323694888054183410183277442293261052541374857284497237962662620855135939824622988307595075856990986582012720735574514707815264844799567498465207543168009051376756587772897126378687641924329456116477049835116043182077902161326553265532816878880281512813885409158321330823*x35
, x31 + 141078286128291606630886906203072934632408661764128821597920658704854485805633020806957657713632945031290388449823774821488941714667731518487834565143893877341057614024612832596966360591884845977083196942329404619897824672205188951576866929732021840241537949541270166963322437279028125919535326441691197810631*x35
, x32 + 105847412828833745276717423602257876160277623745479589037842892793027423939057283725332111575662078806330258478369209968258679073128534166930433256734995914750252215493486176720949241044095285350205653833789446170058359729058614890245422133723660613956809251535159590261672237566016682614798340416609229149021*x35
, x33 + 45711862805354534906742779943507680355899773895103554341403778288529200700102287317028309961984299852963160384174308242754253285488661259924287664351789425051741871468721865195752710664200735393651489639562227565996851319843150600380563120075590512281290529230858068062579443028375841475355563912246241773652*x35
, x34 + 139803356432184693666278113668310134740282635727294542044161753517704900914391647620184933895031484521623703972833683225801039211863739895484987908680664234735385294166422528398624690126736397141969179835462084570613942444022749094252175836602057186156665379674145616238353698127375512970409990421704117995781*x35]

coeffs = [1]

for i in w[1:]:
    coeffs.append(-i.coefficients()[-1])

x_35 = alpha_sum_rsa * pow(pow(sum(coeffs), 65537, N) * pow(double_alphas[-1], 32768, N), -1, N) % N

alphas = []

for i in w[1:]:
    alphas.append(-i(x35 = x_35).coefficients()[-1] % N)
alphas.append(x_35)

G = make_G(R, alphas)
step = ceil(512/k)
lb = [ZZ(i) - error_range for i in p_encoded] + [0 for i in range(k)]
ub = [ZZ(i) + error_range for i in p_encoded] + [2**step for i in range(k)]

mat = block_matrix(
    [
        [G.change_ring(ZZ), 1],
        [N * matrix.identity(ZZ, n), 0]
    ]
)

res = lll_cvp.solve_inequality(
    mat,
    lb,
    ub,
    cvp=partial(lll_cvp.kannan_cvp, reduction=lambda M: M.LLL(), weight=None),
)[-8:]

p_ = int(sum([int(res[i]) * 2**(step * i) for i in range(k)]))

K.<p_x> = PolynomialRing(Zmod(N))

f = p_x + p_

p = int(p_ + small_roots(f, [2**step], m = 9, d= 4)[0][0])
q = int(N // p)

mp = codes.GeneralizedReedSolomonCode(vector(GF(p), alphas), k).decode_to_message(vector(GF(p), key_encoded))
mq = codes.GeneralizedReedSolomonCode(vector(GF(q), alphas), k).decode_to_message(vector(GF(q), key_encoded))

key = []

for i in range(len(mp)):
    key.append(crt([int(mp[i]), int(mq[i])], [p, q]))

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key = hashlib.sha256(str(vector(Zmod(N), key)).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(encrypted_flag))
```

### 4. xiyi

---

**server.py**

```py
"""Calculate the inner product of client's xs and server's ys without leaking ys by homomorphic encryption.

- Each of client's xs, x, is encrypted to enc_x = encrypt(x) and is sent to the server.
- The server calculates enc_alpha = enc_x^y * (-beta), where beta is randomly generated.
- The client can get alpha = decrypt(enc_alpha) such that x * y = alpha + beta because of the homomorphic encryption.
- Finally, the server sends the sum of beta and the client gets the inner product by sum(alpha) + sum(beta).
"""

import json
import os
import signal
from secrets import randbelow

from Crypto.Util.number import isPrime

from lib import Cryptosystem, Pt, Pubkey
from params import L, M, N

flag = os.getenv("FLAG", "SECCON{this_is_not_a_flag}")


def input_json(prompt: str) -> dict:
    params = json.loads(input(prompt))
    assert isinstance(params, dict)
    return params


if __name__ == "__main__":
    signal.alarm(300)

    # initialize
    ys = [randbelow(M) for _ in range(L)]

    # 2: (client) --- n, enc_xs ---> (server) --- enc_alphas, beta_sum_mod_n ---> (client)
    params = input_json('{"n": ..., "enc_xs": [...]} > ')
    n, enc_xs = params["n"], params["enc_xs"]
    assert isinstance(n, int) and n > 0
    assert isinstance(enc_xs, list) and len(enc_xs) == L and all([isinstance(x, int) for x in enc_xs])
    C = Cryptosystem.from_pubkey(Pubkey(n))
    enc_alphas = []
    betas = []
    for enc_x, y in zip(enc_xs, ys, strict=True):
        r = Pt(randbelow(n))
        enc_alpha = C.add(C.mul(enc_x, Pt(y)), C.encrypt(r))
        beta = -r % n
        enc_alphas.append(enc_alpha)
        betas.append(beta)
    beta_sum_mod_n = sum(betas) % n
    print(json.dumps({"enc_alphas": enc_alphas, "beta_sum_mod_n": beta_sum_mod_n}))

    # BTW, can you guess ys?
    params = json.loads(input('{"ys": [...], "p": ..., "q": ...} > '))
    guessed_ys, p, q = params["ys"], params["p"], params["q"]
    assert (
        n == p**2 * q and p.bit_length() == q.bit_length() == N and p != q and isPrime(p) and isPrime(q)
    ), "Don't cheat me!"
    if guessed_ys == ys:
        print("Congratz!")
        print(flag)
    else:
        print("Wrong...")
        print(f"{ys = }")
```

---

#### 1. Tổng quan

+ Hàm mã hóa chính như sau:

$a = x ^ y * g ^ r * h ^ s$

trong đó:
+ a là kết quả enc_alphas được trả ra
+ s, r là số ngẫu nhiên `s, r < n`
+ `g = n // 2`
+ `h = g ^ n`
+ x là số mà mình gửi lên

Chúng ta đã biết a, g trong đó mình có quyền gửi n = p ^ 2 * q, x trong đó p, q là số nguyên tố N bit và x là số bất kỳ.
#### 2. Solution
Viết lại hàm trên như sau

$a = x ^ y * g ^ r * g ^ (n * s) \pmod(p ^ 2 * q)$

$a = x ^ y * g ^ (r + n * s) \pmod(p ^ 2 * q)$

do mình có thể chọn x nên mình gửi x = 1 + k * p khi đó ta dễ có:

+ $a = (1 + p) ^ y * g ^ (r + n * s) \pmod(p ^ 2 * q)$

nên 

+ $a = g ^ (r + n * s) \pmod(p)$

do p mình có thể chọn nên gửi p là số smooth khiến ta có thể dễ dàng tính được $r + n * s \pmod{p - 1}$

+ $a = (1 + p) ^ y * g ^ (r + n * s) \pmod(q)$

với k = gcd(p - 1, q - 1)
thì `p = k * k_p + 1` và `q = k * k_q + 1`

khi đó $r + n * s \pmod{p - 1}$ tương đương với $r + n * s \pmod{k * k_p} \to r + n * s = h_1 \pmod{k}$

khi đó ta chỉ cần brute $r + n * s = h_2 \pmod{k_q}$ khi đó ta chỉ cần crt như sau:

+ $r + n * s = h_2 \pmod{k_q}$
+ $r + n * s = h_1 \pmod{k}$

chúng ta sẽ có $r + n * s \pmod{k * k_q} \to r + n * s \pmod{q - 1} = l$

với $a = (1 + p) ^ y * g ^ (l) \pmod(q)$ thì ta có thể dis log để tìm y do `y < 2 ** 256 < q`

#### 3. Code

```py

# import os

# set_verbose(0)
# os.environ['PWNLIB_NOTERM'] = '1'
# os.environ['TERM'] = 'linux'

from sage.all import *
import json
from tqdm import trange
from secrets import randbelow
from Crypto.Util.number import *
from pwn import *
from params import *

s = process(["python3", "server.py"])

found = 1
while found:
    
    x = 2 * 2 * 2
    while x.bit_length() < 500:
        x *= getPrime(10)
    pq = []

    if 508 < x.bit_length() < 512:
        for i in trange(1 << (N - 1 - x.bit_length()), 1 <<  (N - x.bit_length())):
            if isPrime(x * i + 1):
                pq.append(int(x * i + 1))
            if len(pq) == 2 and pq[0].bit_length() == pq[1].bit_length() == N:
                print(pq)
                print(pq[0], pq[1], pq[0].bit_length(), pq[1].bit_length())
                found = 0
                break

q, p = pq
n = p ** 2 * q
g = n // 2

enc_xs = [1 + p for i in range(L)]
s.sendlineafter(b"> ", json.dumps({"n": n, "enc_xs": enc_xs}).encode())

params = json.loads(s.recvline().strip().decode())
enc_alphas, beta_sum_mod_n = params["enc_alphas"], params["beta_sum_mod_n"]

ys = []

k = gcd(p - 1, q - 1)

for e in enc_alphas:
    

    h1 = discrete_log(GF(p)(e), GF(p)(g))
    for i in trange(2, (q - 1) // k):
        tmp = crt([i, h1 % k], [(q - 1) // k, k])
        
        l_2 = discrete_log(GF(q)(pow(g, tmp, q)), GF(q)(1 + p))
        l_1 = discrete_log(GF(q)(e % q), GF(q)(1 + p))
        y = (l_1 - l_2) % (q - 1)
        
        if int(y).bit_length() <= 256:
            ys.append(int(y))
            break


s.sendlineafter(b"> ", json.dumps({"ys": [int(_) for _ in ys], "p": int(p), "q": int(q)}).encode())
print(s.recvline().strip().decode())  # Congratz! or Wrong...
print(s.recvline().strip().decode())  # flag or ys
```