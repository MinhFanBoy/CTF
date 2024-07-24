
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
