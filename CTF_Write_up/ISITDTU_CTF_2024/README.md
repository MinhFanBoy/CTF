
Tables_of_contens
=================

+ Trong giải này mình không có làm được bài nào, đây là bài viết mình tự tìm hiểu sau khi đã tham khảo hint của các anh cũng như các wu đã được public.

### 1. share_mixer 

---

**_chall.py_**

```py

import random   # TODO: heard that this is unsafe but nvm
from Crypto.Util.number import getPrime, bytes_to_long

flag = bytes_to_long(open("flag.txt", "rb").read())
p = getPrime(256)
assert flag < p
l = 32

def share_mixer(xs):
    cs = [random.randint(1, p - 1) for _ in range(l - 1)]
    cs.append(flag)

    # mixy mix
    random.shuffle(xs)
    random.shuffle(cs)

    shares = [sum((c * pow(x, i, p)) %
                  p for i, c in enumerate(cs)) % p for x in xs]
    return shares

if __name__ == "__main__":
    try:
        print(f"{p = }")
        queries = input("Gib me the queries: ")
        xs = list(map(lambda x: int(x) % p, queries.split()))

        if 0 in xs or len(xs) > 256:
            print("GUH")
            exit(1)

        shares = share_mixer(xs)
        print(f"{shares = }")
    except:
        exit(1)

```
---

#### 1. Tổng quan

+ Bài sẽ cho mình nhập một chuỗi `xs = list(map(lambda x: int(x) % p, queries.split()))` dưới dạng list với tối đa 256 phần tử và trả lại kết quả của list đó sau khi đi qua hàm `share_mixer`
+ Hàm `share_mixer` như sau:
```py
def share_mixer(xs):
    cs = [random.randint(1, p - 1) for _ in range(l - 1)]
    cs.append(flag)

    # mixy mix
    random.shuffle(xs)
    random.shuffle(cs)

    shares = [sum((c * pow(x, i, p)) %
                  p for i, c in enumerate(cs)) % p for x in xs]
    return shares
```

Mình sẽ có 32 hệ số, trong đó có 31 hệ số ngẫu nhiên và 1 hệ số còn lại là flag. Từ 32 hệ số đó ta có thể định nghĩa 1 hàm như sau:

`P(x) = c₁ + c₂x + c₃x² + ... + c₃₁x³⁰ + flag*x³¹ mod p`

trong đó p là số nguyên tố ngẫu nhiên được tạo từ server. Với mỗi xs mình nhập vào nó sẽ trả lại kết quả của hàm đó dưới dạng một danh sách kết quả của các hàm $P(x_1), P(x_2), ...$ không theo thứ tự mà mình đã gửi.

#### 2. Solution

+ Vậy mục tiêu cơ bản của bài này là ta phải tìm lại được tất cả các hệ số của $P(x)$ với 256 phần tử có thể gửi.
+ Do đây là hàm số nên mỗi một $x$ sẽ luôn trả lại một kết quả xác định. Khi mình gửi một số `[1]` thì mình sẽ có kết quả của `[P(1)]`, tương tự như vậy ta có thể lợi dụng điểm này như sau:
    + Ta gửi mối một hệ số một số lần khác nhau thì số lần xuất hiện của kết quả tương ứng với số phần tử nhập vào. Tương tự như sau, với list `[1, 2, 2]` thì ta sẽ có một danh sách kết quả có thể là `[P(2), P(2), P(1)]` hoặc `[P(2), P(1), P(2)]`, tuy vị trí có khác nhau nhưng ta có thể dễ đoán được kết quả dựa vào số lần xuất hiện.
    + Tương tự như vậy, nhưng trong bài này ta chỉ gửi được 256 phần tử < `len(sum(i * [i] for i in range(32)))` nên mình tách ra thành các đoạn nhỏ hơn như sau
    ```py
    for i in range(1, 21):
        index += i*[i]
        lll[i].append(i)

    for i in range(21, 26):
        index += [i]
        lll[1].append(i)

    for idx, i in enumerate(range(26, 33)):
        index += (idx+2)*[i]
        lll[idx+2].append(i)
    ```
    khi đó các phần tử xuất hiện một lần có thể là `x_9, x_10, x_11, x_12, x_13, x_14, x_15, x_16, x_17, x_18, x_19, x_20`, các phần tử có thể xuất hiện 2 lần là `x_2, x_26`, tương tự như thế cho các phần tử còn lại xong ta có thể brute các giá trị có thể với $6! * 2 ^ 7$ trường hợp. Xong từ đó ta có 32 pt, 32 ẩn và ta chỉ cần phải giải ma trận là ra.

#### 3. Code

```py

from pwn import *
from Crypto.Util.number import long_to_bytes
from sage.all import *
import itertools
from tqdm import *
# s = connect("35.187.238.100", 5001)

# s.recvuntil(b'"')
# prefix = str(s.recvuntil(b'"')[:-1].decode().strip())
# s.recvuntil(b'"')
# difficulty = len(str(s.recvuntil(b'"')[:-1].decode().strip()))

# p = process(['python3', 'solver_proof.py', prefix, str(difficulty)])

# output = p.recvline()[:-1].decode().strip()
# p.close()

# s.sendline(output)

s = process(['python3', 'chall.py'])
s.recvuntil(b"p = ")
p = int(s.recvline()[:-1].decode().strip())

index = []
lll = [[] for i in range(32)]
for i in range(1, 21):
    index += i*[i]
    lll[i].append(i)

for i in range(21, 26):
    index += [i]
    lll[1].append(i)

for idx, i in enumerate(range(26, 33)):
    index += (idx+2)*[i]
    lll[idx+2].append(i)

print(lll)
xs = ' '.join(map(str, index))
s.recvuntil(b"Gib me the queries: ")
s.sendline(xs)
s.recvuntil(b"shares = ")
shares = eval(s.recvline()[:-1].decode().strip())
# print(f"{shares = }")
# print(f"{p = }")

d = {_: shares.count(_) for _ in set(shares)}

tmp = [[] for i in range(32)]
for _, __ in d.items():
    tmp[__ - 1].append(_)

for i, j in enumerate(tmp):
    print(i, len(j))
x_9, x_10, x_11, x_12, x_13, x_14, x_15, x_16, x_17, x_18, x_19, x_20 = [_[0] for _ in tmp[8:20]]
for _ in tqdm(itertools.permutations(tmp[0])):
    x_1, x_21, x_22, x_23, x_24, x_25 = [l for l in _]
    for __ in itertools.permutations(tmp[1]):
        x_2, x_26 = __
        for ___ in itertools.permutations(tmp[2]):
            x_3, x_27 = ___
            for ____ in itertools.permutations(tmp[3]):
                x_4, x_28 = ____
                for _____ in itertools.permutations(tmp[4]):
                    x_5, x_29 = _____
                    for ______ in itertools.permutations(tmp[5]):
                        x_6, x_30 = ______
                        for _______ in itertools.permutations(tmp[6]):
                            x_7, x_31 = _______
                            for ________ in itertools.permutations(tmp[7]):
                                x_8, x_32 = ________
                            
                            
                                M = [
                                    [pow(i, tmp, p) for tmp in range(32)] for i in range(1, 33)
                                ]
                                M = matrix(Zmod(p), M)
                                X = column_matrix(Zmod(p), [x_1, x_2, x_3, x_4, x_5, x_6, x_7, x_8, x_9, x_10, x_11, x_12, x_13, x_14, x_15, x_16, x_17, x_18, x_19, x_20, x_21, x_22, x_23, x_24, x_25, x_26, x_27, x_28, x_29, x_30, x_31, x_32])
                                
                                tmp_ = M.solve_right(X)
                                for lmao in tmp_:
                                    xxx = long_to_bytes(int(lmao[0]))
                                    try:
                                        print(xxx.decode())
                                    except:
                                        pass
```

### 2. share_mixer2

---
```py
import random   # TODO: heard that this is unsafe but nvm
from Crypto.Util.number import getPrime, bytes_to_long

flag = bytes_to_long(open("flag.txt", "rb").read())
p = getPrime(256)
assert flag < p
l = 32

def share_mixer(xs):
    cs = [random.randint(1, p - 1) for _ in range(l - 1)]
    cs.append(flag)
    
    # mixy mix
    random.shuffle(xs)
    random.shuffle(cs)

    shares = [sum((c * pow(x, i, p)) % p for i, c in enumerate(cs)) % p for x in xs]
    return shares


if __name__ == "__main__":
    try:
        print(f"{p = }")
        queries = input("Gib me the queries: ")
        xs = list(map(lambda x: int(x) % p, queries.split()))

        if 0 in xs or len(xs) > 32:
            print("GUH")
            exit(1)

        shares = share_mixer(xs)
        print(f"{shares = }")
    except:
        exit(1)
```
---

#### 1. Tổng quan

+ Bài này nhìn chung thì cũng giống như bài trước nhưng lần này ta chỉ có thể gửi tối đa 32 phần tử.

#### 2. Solution

+ Do chỉ có 32 lần nên ta không thể áp dụng cách trên để giải được nên ta phải tiếp cần theo một cách khác.
+ Ta có thể thấy rằng tất cả các phép tính đều trong modulo p mà theo định lý Lagrange, trong trường F_p, bậc của mọi phần tử phải chia hết cho `phi(p) = p - 1`
+ Vậy nếu ta có thể tạo ra một nhóm con có 32 phần tử thì Các lũy thừa của g sẽ tạo thành chu kỳ: g, g², g³, ..., g³², g³³ ≡ g, ...
+ Khi đó hàm `P(x) = c₁ + c₂x + c₃x² + ... + c₃₁x³⁰ + flag*x³¹ mod p` với một phần tử ta có:

```py
P(g) = c₁ + c₂g + c₃g² + ... + c32*g³¹
P(g²) = c₁ + c₂g² + c₃g⁴ + ... + c32*g⁶²
P(g³) = c₁ + c₂g³ + c₃g⁶ + ... + c32*g⁹³
...
```

khi cộng tất cả các share thì ta có :

```py
sum(shares) = (c₁ + c₁ + ... + c₁) + (c₂g + c₂g² + ... + c₂g³²) +... + (c32*g³¹ + c32*g⁶² + ...) (mod p)
```

Mà ta cũng có đây là cấp số nhân với công bội `q = g` và số đầu `a = g`.Theo công thức tổng cấp số nhân: `Sn = a(q^n - 1)/(q - 1)`
=> `Tổng = g(g³² - 1)/(g - 1) = 0 (vì g³² ≡ 1)`
Khi đó

$sum(shares) = c₁*32 + c₂ * 0 +... + c_{32} * g ^ {32} * 0 = c_1 * 32 \to c_1 = sum * 32 ^ {-1} \pmod{p}$

Mình chỉ cần chạy cho đến khi nào flag random vào c1 là xong.

#### 3. Code

```py

from pwn import *
from Crypto.Util.number import long_to_bytes
from sage.all import *
import itertools
from tqdm import *

context.log_level = 'warn'

while True:
    while True:
        s = process(['python3', 'chall.py'])
        s.recvuntil(b"p = ")
        p = int(s.recvline()[:-1].decode().strip())

        if (p - 1) % 32 == 0:
            break
        s.close()

    xs = ' '.join(map(str, [pow(5, i * (p - 1) // 32, p) for i in range(32)]))
    s.recvuntil(b"Gib me the queries: ")
    s.sendline(xs.encode())
    s.recvuntil(b"shares = ")
    shares = eval(s.recvline()[:-1].decode().strip())

    try:
        print(long_to_bytes(sum(shares) * pow(32, -1, p) % p).decode())
        exit()
    except:
        pass
```

### 3. sign

---

**_chall.py_**

```py
#!/usr/bin/env python3

import os

from Crypto.Util.number import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

flag = b'ISITDTU{aaaaaaaaaaaaaaaaaaaaaaaaaa}'
flag = os.urandom(255 - len(flag)) + flag


def genkey(e=11):
    while True:
        p = getPrime(1024)
        q = getPrime(1024)
        if GCD(p-1, e) == 1 and GCD(q-1, e) == 1:
            break
    n = p*q
    d = pow(e, -1, (p-1)*(q-1))
    return RSA.construct((n, e, d))


def gensig(key: RSA.RsaKey) -> bytes:
    m = os.urandom(256)
    h = SHA256.new(m)
    s = PKCS1_v1_5.new(key).sign(h)
    return s


def getflagsig(key: RSA.RsaKey) -> bytes:
    return long_to_bytes(pow(bytes_to_long(flag), key.d, key.n))


key = genkey()

while True:
    print(
        """=================
1. Generate random signature
2. Get flag signature
================="""
    )

    try:
        choice = int(input('> '))
        if choice == 1:
            sig = gensig(key)
            print('sig =', sig.hex())
        elif choice == 2:
            sig = getflagsig(key)
            print('sig =', sig.hex())
    except Exception as e:
        print('huh')
        exit(-1)
```

---

#### 1. Tổng quan

+ Bài này khá ngắn gọn, ta có rất nhiều sig dạng `PKCS1_v1_5` và có `long_to_bytes(pow(bytes_to_long(flag), key.d, key.n))` với `e = 11` nhưng ta chưa có `n` nên ta phải cần tìm lại n là dễ dàng có flag.

#### 2. Soulution

+ Dạng `PKCS1_v1_5` có cấu trúc cơ bản như sau: `00 01 FF FF ... FF 00 + DER + hash` đây là sha256 nên DER là '3031300d060960864801650304020105000420'

+ Vậy ta có dạng $s = m ^ d \pmod(p)$ nên $s ^ e - m = k * n $ với `m0 =  00 01 FF FF ... FF 00 + DER + 00 * 32`, `m = m0 + m1`, `0 < m1 < 256 ** 32`
Ta có 
```
s1 ^ e - m0 = k1 * n + m1
s2 ^ e - m0 = k2 * n + m2

...
```

+ Đến đây ta có thể sử dụng agcd để giải bài toán này. Sử dụng ma trận này với $\lambda = log_2{m_1}$

$
\mathbf{B} = \begin{pmatrix}
2^{\lambda+1} & s_1^e - m_0 & s_2^e - m_0 & \cdots & s_n^e - m_0 \\
& -(s_0^e - m_0) & & & \\
& & -(s_0^e - m_0) & & \\
& & & \ddots & \\
& & & & -(s_0^e - m_0)
\end{pmatrix}
$

Sau khi lll ma trận trên, ta có kết quả là `[k0 * 2 ** 33, k0 * r1 - k1 * r0, ...]`, từ đó thì có thể tìm lại k0. Khi có k0 thì ta có thể tìm lại $n = (s_1 ^ e - m_0) // k_0$ do m1 rất nhỏ khi so với n hoặc k. Và từ đó ta có thể dễ ràng tìm ra flag.

#### 3. Code

```py

from pwn import *
from tqdm import trange
from Crypto.Util.number import *
from sage.all import *

import os
from re import findall
from subprocess import check_output

def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

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

# s = connect("35.187.238.100", 5003)
s = process(["python3", "chall.py"])
# s.recvuntil(b'"')
# prefix = str(s.recvuntil(b'"')[:-1].decode().strip())
# s.recvuntil(b'"')
# difficulty = len(str(s.recvuntil(b'"')[:-1].decode().strip()))

# p = process(['python3', 'solver_proof.py', prefix, str(difficulty)])

# output = p.recvline()[:-1].decode().strip()
# p.close()

# s.sendline(output)

l = []
em = bytes_to_long(b'\x00\x01' + (b'\xFF' * 202) + b'\x00' + bytes.fromhex('3031300d060960864801650304020105000420') + b"\x00" * 32)

for _ in trange(30):
    s.recvuntil(b"> ")
    s.sendline(b"1")
    
    s.recvuntil(b"sig =")
    l.append(int(s.recvline()[:-1].decode().strip(), 16) ** 11 - em)
s.recvuntil(b"> ")
s.sendline(b"2")

s.recvuntil(b"sig =")
enc = int(s.recvline()[:-1].decode().strip(), 16)

A = diagonal_matrix([-l[0]] * 29)
B = matrix(l[1:])
w = 2 ** 32

M = block_matrix([
    [matrix([[w]]), B],
    [0, A]
])

for i in flatter(M):
    # print(i[0] % 2 ** 33, i[0])
    n_ = l[0] // (i[0] // 2 ** 32)
    # print(int(n_).bit_length())
    if int(n_).bit_length() == 2048:
        print(long_to_bytes(int(pow(enc, 11, n_))))
```

