
Table_of_contents
=================

## HIT_CON 2024

Viết lại những gì tìm hiểu được trong giải và được tham khảo từ nhiều người khác nhau.

### 1. Zkpof

---

**_Chall.py_**:

```py
#!/usr/bin/env python3
from Crypto.Util.number import getPrime, getRandomRange
from math import floor
import json, random, os

# https://www.di.ens.fr/~stern/data/St84.pdf
A = 2**1000
B = 2**80


def keygen():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    return n, phi


def zkpof(z, n, phi):
    # I act as the prover
    r = getRandomRange(0, A)
    x = pow(z, r, n)
    e = int(input("e = "))
    if e >= B:
        raise ValueError("e too large")
    y = r + (n - phi) * e
    transcript = {"x": x, "e": e, "y": y}
    return json.dumps(transcript)


def zkpof_reverse(z, n):
    # You act as the prover
    x = int(input("x = "))
    e = getRandomRange(0, B)
    print(f"{e = }")
    y = int(input("y = "))
    transcript = {"x": x, "e": e, "y": y}
    return json.dumps(transcript)


def zkpof_verify(z, t, n):
    transcript = json.loads(t)
    x, e, y = [transcript[k] for k in ("x", "e", "y")]
    return 0 <= y < A and pow(z, y - n * e, n) == x


if __name__ == "__main__":
    n, phi = keygen()
    print(f"{n = }")

    rand = random.Random(1337)  # public, fixed generator for z
    for _ in range(0x137):
        try:
            z = rand.randrange(2, n)
            t = zkpof(z, n, phi)
            assert zkpof_verify(z, t, n)
            print(t)
            if input("Still not convined? [y/n] ").lower()[0] != "y":
                break
        except Exception as e:
            print(f"Error: {e}")
    print(
        "You should now be convinced that I know the factorization of n without revealing anything about it. Right?"
    )
    for _ in range(floor(13.37)):
        z = rand.randrange(2, n)
        t = zkpof_reverse(z, n)
        assert zkpof_verify(z, t, n)
        print(t)
    print("flag{test}")

```

---

#### Tổng quan

Đây là một bài sử dụng `proof-of-knowledge protocol` làm giao thức chuyển khóa, một số điểm cần chú ý là:

+ `r = getRandomRange(0, A)` chọn r ngẫu nhiên và tính $x = z ^ r \pmod{n}$ với x, n là những public key đã được biết từ trước.
+ Cho chọn một số e và tính `y = r + (n - phi) * e`
+ sever nhận lại x và tính $x_ = z ^ {y -  n * e} \pmod{n}$ và kiểm tra x_ == x vì $x_ = z ^ y = z ^ {r + (n - phi) * e - n * e} = z ^ r * z ^ {(n - phi) * e  - n * e} = z ^ r = x\pmod{n}$

Và trong thử thách này e, r đã được chặn giới hạn r < $2 ^ {1000}$, e < $2 ^ {80}$. Ta phải thực hiện thành công 13 lần điều này khi biết e, n.
Ngoài ra các tham số cũng được tiết lộ bởi hàm `rand = random.Random(1337)` khiến r không đổi.

#### Solution


Ta có `0x137` lần proof với server

```py
    for _ in range(0x137):
        try:
            z = rand.randrange(2, n)
            t = zkpof(z, n, phi)
            assert zkpof_verify(z, t, n)
            print(t)
            if input("Still not convined? [y/n] ").lower()[0] != "y":
                break
        except Exception as e:
            print(f"Error: {e}")
```
Khi nhìn vào hàm `zkpof` có thể thấy

```py
def zkpof(z, n, phi):
    # I act as the prover
    r = getRandomRange(0, A)
    x = pow(z, r, n)
    e = int(input("e = "))
    if e >= B:
        raise ValueError("e too large")
    y = r + (n - phi) * e
    transcript = {"x": x, "e": e, "y": y}
    return json.dumps(transcript)
```

điều kiện `e >= B` khiến nó trở nên không chặt chẽ và có thể bị tấn công `CVE-2020-10735`

Khi gửi số có |x| > 10 ^ 4300 thì sever sẽ trả lại lỗi error số. Vậy nên ở đây mình có thể gửi số âm rất lớn để server lỗi.

Khi đó mình có $10 ^ {4300} >= r + (n - {phi}) * e$ -> ${n - {phi}} ~= 10 ^ {4300} / |e|$ vì khi đó r rất nhỏ nếu so với các số khác. Đến đây mình áp dụng tìm kiếm nhị phân với số e để có thấy lấy được giá trị xấp xỉ `k = n - phi`.

Với `phi = (p - 1)(q - 1) = n - q - p + 1` -> `k ~= p + q` -> `p - q = (k ** 2 - 4 * n) ^ (1 / 2)`

và tới đó ta có thể tìm lại số xấp xỉ p. Phần còn lại ta chỉ cần dùng coppersmith là có thể tìm lại p.

với p thì ta có thể tìm lại phi và với r đã biết thì có thể dễ dàng hoàn thành bài.

#### Code

```py
#!/usr/bin/env python3
from Crypto.Util.number import *
from math import floor
import json, random, os
from pwn import *
from tqdm import *

import itertools

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()

    if isinstance(f, Polynomial):
        x, = polygens(f.base_ring(), f.variable_name(), 1)
        f = f(x)

    R = f.base_ring()
    N = R.cardinality()
    
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

s = process(['python3', 'server.py'])
rand = random.Random(1337)

A = 2**1000
B = 2**80

Max = 10 ** 4300
l = 0
r = 1 << 513

s.recvuntil(b"n = ")
n = int(s.recvline().strip().decode())

for i in tqdm(range(0x137)):
    z = rand.randrange(2, n)
    s.recvuntil(b"e = ")
    m = (l + r) // 2

    s.sendline("-" + str(Max // m))
    tmp = s.recvline()

    if b"Exceeds the limit" in tmp:
        l = m
    else:
        r = m

k = (isqrt(l ** 2 - 4 * n) + l) // 2
PR.<x> = PolynomialRing(Zmod(n))

f = k + x

q = small_roots(f, [2 ** 200], 10, 4)[0][0] + k
print(is_prime(q))
p = int(n) // int(q)

for _ in range(floor(13.37)):
    z = rand.randrange(2, n)
    s.recvuntil("x = ")
    s.sendline(str(pow(z, r, n)).encode())
    s.recvuntil("e = ")
    e = s.recvline().strip().decode()
    s.recvuntil("y = ")
    y = r + (int(n) - (int(p) - 1) * (int(q) - 1)) * int(e)
    s.sendline(str(y).encode())
    print(s.recvline())
print(s.recv())

```

### 2. pcbc

---

**_Chall.py_**:

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from functools import reduce
from secret import flag
import os
import json

BLOCK_SIZE = 16
key_ctr1 = os.urandom(BLOCK_SIZE)
key_ctr2 = os.urandom(BLOCK_SIZE)
key_cbc = os.urandom(BLOCK_SIZE)
nonce1 = os.urandom(8)
nonce2 = os.urandom(8)

def AES_ECB_enc(key, message):
    enc = AES.new(key, AES.MODE_ECB)
    return enc.encrypt(message)

def AES_ECB_dec(key, message):
    enc = AES.new(key, AES.MODE_ECB)
    return enc.decrypt(message)

# Returning a block each time
def get_blocks(message):
    for i in range(0, len(message), BLOCK_SIZE):
        yield message[i:i+BLOCK_SIZE]
    return

# Takes any number of arguements, and return the xor result.
# Similar to pwntools' xor, but trucated to minimum length
def xor(*args):
    _xor = lambda x1, x2: x1^x2
    return bytes(map(lambda x: reduce(_xor, x, 0), zip(*args)))


def counter(nonce):
    count = 0
    while count < 2**(16 - len(nonce)):
        yield nonce + str(count).encode().rjust(16-len(nonce), b"\x00")
        count+=1
    return


def encrypt(message):
    cipher = b""
    iv = os.urandom(BLOCK_SIZE)
    prev_block = iv
    counter1 = counter(nonce1)
    counter2 = counter(nonce2)
    for block in get_blocks(pad(message, BLOCK_SIZE)):
        enc1 = AES_ECB_enc(key_ctr1, next(counter1))
        enc2 = AES_ECB_enc(key_cbc, xor(block, prev_block, enc1))
        enc3 = AES_ECB_enc(key_ctr2, next(counter2))
        enc4 = xor(enc3, enc2)
        prev_block = xor(block, enc4)
        cipher += enc4

    return iv + cipher

def decrypt(cipher):
    message = b""
    iv = cipher[:16]
    cipher_text = cipher[16:]

    prev_block = iv
    counter1 = counter(nonce1)
    counter2 = counter(nonce2)
    for block in get_blocks(cipher_text):
        dec1 = AES_ECB_enc(key_ctr2, next(counter2))
        dec2 = AES_ECB_dec(key_cbc, xor(block, dec1))
        dec3 = AES_ECB_enc(key_ctr1, next(counter1))
        message += xor(prev_block, dec2, dec3)
        prev_block = xor(prev_block, dec2, block, dec3)

    return unpad(message, BLOCK_SIZE)

def main():
    certificate = os.urandom(8) + flag + os.urandom(8)
    print(f"""
*********************************************************

Certificate as a Service

*********************************************************

Here is a valid certificate: {encrypt(certificate).hex()}

*********************************************************""")
    while True:
        try:
            cert = bytes.fromhex(input("Give me a certificate >> "))
            if len(cert) < 32:
                print("Your certificate is not long enough")

            message = decrypt(cert)
            if flag in message:
                print("This certificate is valid")
            else:
                print("This certificate is not valid")
        except Exception:
            print("Something went wrong")
            
if __name__ == "__main__":
    main()

```

---

Đây là một bài AES sử dụng mod pcbc nhưng được kẹp với 2 mod CTR khác.

#### Tổng quan

Đây là ảnh mô tả quá trình mã hóa của hàm `encrypt`

![image](https://github.com/user-attachments/assets/5e8529c9-1977-4b66-890a-af1305808cce)

Tương tự ta có thế hình dung hàm giải mã `decrypt` như sau:

![image](https://github.com/user-attachments/assets/e4e1440b-0ab9-475c-9864-7a3ef3525826)

Hình ảnh được lấy từ [đây](https://mystiz.hk/posts/2024/2024-07-20-hitcon-ctf/#pcbc-revenge)

Thử thách có cho ta giải mã enc mà ta gửi lên không giới hạn lần tùy vào đầu ra của kết quả mã hóa mà ta có các dữ liệu khác nhau được trả lại.

```py
            if flag in message:
                print("This certificate is valid")
            else:
                print("This certificate is not valid")
        except Exception:
            print("Something went wrong")
```

#### Solution

Mình có thấy rằng

```
        dec1 = AES_ECB_enc(key_ctr2, next(counter2))
        dec2 = AES_ECB_dec(key_cbc, xor(block, dec1))
        dec3 = AES_ECB_enc(key_ctr1, next(counter1))
```

trong quá trình mã hóa 2 hàm AES-CTR không đóng vai trò quá quan trọng vì nó luôn cố định nên miễn là mình gửi enc đúng theo thứ tự block thì nó sẽ không quá ảnh hưởng tới chương trình.

Ngoài ra sau khi mã hóa hàm `decrypt` sẽ thực hiện hàm `unpad`

```py
    return unpad(message, BLOCK_SIZE)
```

khiến chúng ta thấy rằng với iv có thể điều khiển và hàm `Exception` khiến ta có thể sử dụng padding attack.

Vì ta dễ thấy $m_0 \oplus m^{'}_0 = m_1 \oplus m^{'}_1 = ... = c_0 \oplus {iv}$

nên $m^{'}_0 = c_0 \oplus {iv} \oplus m_0$ ta thay đổi iv để kết quả trả về có thể unpad không bị lỗi thì có thể tìm lại $m_0$
#### Code

```py

from pwn import *

s = process(["python3", "chal.py"])

def padding_oracle(iv, k):
    s.recvuntil(b">> ")
    s.sendline((iv + k).hex().encode())
    
    k = s.recvline()[:-1]
    # print(k)
    if b"Something went wrong" in k:
        return False
    else:
        return True

s.recvuntil(b"certificate: ")
enc = bytes.fromhex(s.recvline().strip().decode())

c = [enc[i:i+16] for i in range(0, len(enc), 16)]

for i in range(1, len(c)):
    
    iv = c[0]
    c_ = c[1: i + 1]
    
    p = [0] * 16
    
    for index in range(15, -1, -1):
        
        for guess in range(256):
            
            iv_ = xor(iv, bytes([0] * index + [guess^ (16 - index)]) + xor(bytes(p[index  + 1:]), bytes([16 - index] * (16 - index - 1))))
            
            if padding_oracle(iv_, b"".join(c_)):
                p[index] = guess 
                break

    print(bytes(p))
```
