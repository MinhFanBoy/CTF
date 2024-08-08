Tables_of_contens
================

## crewCTF_2024_Crypto

**Mình viết dựa trên nhiều solution của người khác do mình trong giải này không có làm được nhiều(làm tư liệu tham khảo) cũng như tìm hiểu thêm về các bài sau giải**

### 1. 4ES

---

**_chal.py_**:

```py
#!/usr/bin/env python3

from hashlib import sha256
from random import choices

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

with open('flag.txt', 'rb') as f:
    FLAG = f.read().strip()

chars = b'crew_AES*4=$!?'
L = 3

w, x, y, z = (
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
)

k1 = sha256(w).digest()
k2 = sha256(x).digest()
k3 = sha256(y).digest()
k4 = sha256(z).digest()

print(w.decode(), x.decode(), y.decode(), z.decode())

pt = b'AES_AES_AES_AES!'
ct = AES.new(k4, AES.MODE_ECB).encrypt(
         AES.new(k3, AES.MODE_ECB).encrypt(
             AES.new(k2, AES.MODE_ECB).encrypt(
                 AES.new(k1, AES.MODE_ECB).encrypt(
                     pt
                 )
             )
         )
     )

key = sha256(w + x + y + z).digest()
enc_flag = AES.new(key, AES.MODE_ECB).encrypt(pad(FLAG, AES.block_size))

with open('output.txt', 'w') as f:
    f.write(f'pt = {pt.hex()}\nct = {ct.hex()}\nenc_flag = {enc_flag.hex()}')
```

**_output.py_**:

```py

pt = 4145535f4145535f4145535f41455321
ct = edb43249be0d7a4620b9b876315eb430
enc_flag = e5218894e05e14eb7cc27dc2aeed10245bfa4426489125a55e82a3d81a15d18afd152d6c51a7024f05e15e1527afa84b
```

---

#### Tổng quan

+ chon ngẫu nhiên 4 key từ trong `chars = b'crew_AES*4=$!?'` mỗi key có 3 ký tự. Lấy từng key để mã hóa `pt = b'AES_AES_AES_AES!'` bằng 4AES và flag flag được mã hóa bằng tổng của 4 key trên.

#### solution

+ Dễ thấy với mỗi khóa như vậy thì ta có tất cả `14 ^ (3 * 4)` trường hợp cặp khóa tất cả nên mình không thể brute để tìm lại khóa như vậy được, nên mình phải chia nhỏ trường hợp lại bằng `meet in the middle` attack vì mình đã có sẵn cả plaintext.

+ Thực hiệm brute 2 key đêr mã hóa plaintext và lưu vào một mảng.
+ Thực hiện tiếp brute 2 khóa mà để giải mã ciphertext nếu bytes giải mã được có trong mảng vừa lưu thì 4 key đó chính là key cần tìm.

#### code


```py
#!/usr/bin/env python3

from hashlib import sha256
from random import choices
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from collections import *
from itertools import *
from tqdm import tqdm

pt = b'AES_AES_AES_AES!'
chars = b'crew_AES*4=$!?'
L = 3
pt = bytes.fromhex("4145535f4145535f4145535f41455321")
ct = bytes.fromhex("edb43249be0d7a4620b9b876315eb430")
enc_flag = bytes.fromhex("e5218894e05e14eb7cc27dc2aeed10245bfa4426489125a55e82a3d81a15d18afd152d6c51a7024f05e15e1527afa84b")

for w in tqdm(combinations(chars, L)):
    for x in combinations(chars, L):
        for y in combinations(chars, L):
            for z in combinations(chars, L):
                w = bytes(w)
                x = bytes(x)
                y = bytes(y)
                z = bytes(z)

                key = sha256(w + x + y + z).digest()
                enc_flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)
                
                try:
                    print(enc_flag.decode())
                except:
                    pass


```


### 2. read in the lines

---

**_chal.py_**:

```py
#!/usr/bin/env python3

from random import shuffle
from Crypto.Util.number import getPrime


with open('flag.txt', 'rb') as f:
    FLAG = f.read().strip()

assert len(FLAG) < 100

encoded_flag = []

for i, b in enumerate(FLAG):
    encoded_flag.extend([i + 0x1337] * b)

shuffle(encoded_flag)

e = 65537
p, q = getPrime(1024), getPrime(1024)
n = p * q
c = sum(pow(m, e, n) for m in encoded_flag) % n

with open('output.txt', 'w') as f:
    f.write(f'{n = }\n{e = }\n{c = }\n')
```

**_output.py_**

```py
n = 11570808501273498927205104472079357777144397783547577003261915477370622451850206651910891120280656785986131452685491947610185604965099812695724757402859475642728712507339243719470339385360489167163917896790337311025010411472770004154699635694228288241644459059047022175803135613130088955955784304814651652968093606122165353931816218399854348992145474578604378450397120697338449008564443654507099674564425806985914764451503302534957447420607432031160777343573246284259196721263134079273058943290282037058625166146116257062155250082518648908934265839606175181213963034023613042840174068936799861096078962793675747202733
e = 65537
c = 7173375037180308812692773050925111800516611450262181376565814072240874778848184114081029784942289615261118103256642605595499455054072839201835361613983341298973366881719999836078559255521052298848572778824157749016705221745378832156499718149327219324078487796923208917482260462508048311400560933782289383624341257636666638574026084246212442527379161504510054689077339758167386002420794571246577662116285770044542212097174474572856621921237686119958817024794843805169504594110217925148205714768001753113572920225449523882995273988088672624172009740852821725803438069557080740459068347366098974487213070886509931010623
```

---

#### Tổng quan

```py
for i, b in enumerate(FLAG):
    encoded_flag.extend([i + 0x1337] * b)
```

+ flag được chia ra thành các ký tự, mỗi ký tự được nhân với phần `pad = (index + 0x1337)`
+ Sau đó mỗi phần này lại được mã hóa RSA 2048 bit và ta có được tổng của tất cả bản mã hóa đó.

#### Solution

+ Dễ thấy mã hóa có dạng như sau:

`(pad_0 * p_0) ^ 65537 + (pad_1 * p_1) ^ 65537 + .... = enc mod(n)`

thực hiện chuyển vế và chuyển trường sang QQ ta có:

`(pad_0 * p_0) ^ 65537 + (pad_1 * p_1) ^ 65537 + .... - enc - k * n == 0`

Bây giờ mình sẽ viết lại phương trình theo cách khác:

`(pad_0 ^ 65537 * p_0 ^ 65537) + (pad_1 ^ 65537 * p_1 ^ 65537)  + .... - enc - k * n == 0`

vì pad_0, pad_1 = (index + 0x1337) nên ta có thể biết được tất cả các pad. Ngoài ra p_0, p_1, ... là các ký tự của flag nên sẽ có độ lớn < 256 nên (p_0) ^ 655537 cũng rất nhỏ so với những phần khác nên mình có thể sử dụng LLL để recover lại từng phần của flag.

Mình xây dựng ma trận như này:

![image](https://github.com/user-attachments/assets/0fd16f75-3900-451e-95be-139da9d420ad)

Và sử dụng LLL là ta có được flag

Note:
Dang ra ma trận ta thu được là (p_0 ^ 65537, p_1 ^ 65537, ...) nhưng vì đang sử dụng LLL nên kết quả của ta sẽ là (p_0, p_1, ...) vì nó tự đưa về vector nhỏ nhất. Và ngoài ra thì phải nhân thêm phần mod n làm hệ số để có thể ra được đáp án.

#### Code

```py

from sage.all import *
from string import *
from Crypto.Util.number import long_to_bytes

n = 11570808501273498927205104472079357777144397783547577003261915477370622451850206651910891120280656785986131452685491947610185604965099812695724757402859475642728712507339243719470339385360489167163917896790337311025010411472770004154699635694228288241644459059047022175803135613130088955955784304814651652968093606122165353931816218399854348992145474578604378450397120697338449008564443654507099674564425806985914764451503302534957447420607432031160777343573246284259196721263134079273058943290282037058625166146116257062155250082518648908934265839606175181213963034023613042840174068936799861096078962793675747202733
e = 65537
c = 7173375037180308812692773050925111800516611450262181376565814072240874778848184114081029784942289615261118103256642605595499455054072839201835361613983341298973366881719999836078559255521052298848572778824157749016705221745378832156499718149327219324078487796923208917482260462508048311400560933782289383624341257636666638574026084246212442527379161504510054689077339758167386002420794571246577662116285770044542212097174474572856621921237686119958817024794843805169504594110217925148205714768001753113572920225449523882995273988088672624172009740852821725803438069557080740459068347366098974487213070886509931010623

F = Zmod(n)

lst = []

length = 100

for i in range(length):
    lst.append(pow(i + 0x1337, e, n))
    
lst.append(n)
I = identity_matrix(ZZ, length + 1)

block = matrix(ZZ, 1, length + 1, lst)

pad = matrix(ZZ, 1, length + 1, [0] * (length + 1))

M = block_matrix([[I, block.T], [pad, ZZ(- c)]])

M = (M).LLL()
M = matrix(F, M)

for i in M:
    if i[-1] == 0:
        t = b""
        for k in i:
            t = t + long_to_bytes(int(ZZ(k)))

        print(t)
```

### 3. Boring LCG

----

**_Chal.py_**:

```py
import os
from sage.all import *
set_random_seed(1337)
Fp = GF(6143872265871328074704442651454311068421530353607832481181)
a, b = Fp.random_element(), Fp.random_element()

flag = (os.getenv('flag') or 'crew{submit_this_if_desperate}').encode()
s = Fp.from_integer(int.from_bytes(flag[len('crew{'):-len('}')], 'big'))

out = []
for _ in range(12): out.extend(s:=a*s+b)
print([x>>57 for x in out])
# [50, 32, 83, 12, 49, 34, 81, 101, 46, 108, 106, 57, 105, 115, 102, 51, 67, 34, 124, 15, 125, 117, 51, 124, 38, 10, 30, 76, 125, 27, 89, 14, 50, 93, 88, 56]
```

----

#### Tổng quát

Đây là mộ bài mã hóa LCG nhưng trong trường p ^ 3.

```py
set_random_seed(1337)
a, b = Fp.random_element(), Fp.random_element()
```

Với a, b đã biết.

```py
print([x>>57 for x in out])
# [50, 32, 83, 12, 49, 34, 81, 101, 46, 108, 106, 57, 105, 115, 102, 51, 67, 34, 124, 15, 125, 117, 51, 124, 38, 10, 30, 76, 125, 27, 89, 14, 50, 93, 88, 56]
```

Tuy nhiên ta chỉ biết được một phần của đầu ra. Và bây giờ ta cần phải tìm lại seed cũng chính là flag.

#### Solution.

Với `seed := a * seed + b` ta thấy:

+ `s_1 = a * s_0 + b`
+ `s_2 = a * s_1 + b = a * (a * s_0 + b) + b = a ^ 2 * s_0 + b * (a + 1)`
+ `s_3 = a * s_2 + b = a * (a * s_1 + b) + b = a ^ 2 * s_1 + b * (a + 1) = ...`
  
...

+ `s_n = a ^ n * s_0 + b * (a ^ (n - 1) - 1) / (a - 1)`

Ở đây ta đã biết $B = b * (a ^ {n - 1} - 1) / (a - 1)$ và A = $a ^ n$ . Tuy nhiên S_n ta chỉ biết S_n >> 57 nên để có thể gần với đầu ra nhất ta lấy trung bình của (x) << 57 và (x + 1) << 57. Khi đó s_n mà ta biết mới chỉ xấp xỉ kết quả thật nên ta phải sử dụng LLL để tìm lại kết quả chính xác.

Dựa và trên ta dễ thấy:

+ $S_n = A * seed + B$
+ $A * seed = (S_n - B)$

Nhưng vấn đề ở đây là A, B, seed đang là các đa thức mà LLL thì ta cần phải có một ma trận nên ta phải biểu diễn lại các đa thức dưới dạng ma trận. Ngoài ra do ở đây mình có rất nhiều hệ phương trình có cùng ẩn seed và khác A, B nên cần biểu diễn thành ma trận sao cho có thể tận dụng được nó.

với f(x) = f0 + f1 * x + f2 * x + ... và g(x) = g0 + g1 * x + g2 * x + ...
![image](https://github.com/user-attachments/assets/ddfe3a02-e951-4a06-afe3-4b51f8cd04f9)

nên 

![image](https://github.com/user-attachments/assets/ec16e07a-935b-4f55-af2b-99aaf35cdb95)

ta có thể biểu diễn thành ma trân f(x) = (f0, f1, f2, .....) để có thể biểu diễn phép tính $f(x) * g(x) = \lambda(x)$

thì 

![image](https://github.com/user-attachments/assets/e24b170a-7962-428e-bf7a-8df2cc93e534)

Code test:

```sage
F.<x> = PolynomialRing(ZZ)

A = 2 + 2 * x + 2 * x^2
B = 2 * x + x ^ 2

A_ = [2, 2, 2, 0, 0, 0]
B_ = [0, 2, 1, 0, 0, 0]

L = [
    [0, 2, 1, 0, 0, 0], 
    [0, 0, 2, 1, 0, 0],
    [0, 0, 0, 2, 1, 0],
    [0, 0, 0, 0, 2, 1], 
    [1, 0, 0, 0, 0, 2], 
    [2, 1, 0, 0, 0, 0], 
]

A_ = vector(A_)
L_ = matrix(L)

print((A_ * L_))
print(A * B)
```

Nhưng đó là trong trường số thực, vậy nên khi tính toán trong trường GF(p ^ 3) sẽ có một chút khác biệt.

#### Code

```sage
import os
from sage.all import *

def cvp(B, t):
    t = vector(ZZ, t)
    B = B.LLL()
    S = B[-1].norm().round()+1
    L = block_matrix([
        [B,         0],
        [matrix(t), S]
    ])
    for v in L.LLL():
        if abs(v[-1]) == S:
            return t - v[:-1]*sign(v[-1])
    raise ValueError('cvp failed?!')

set_random_seed(1337)
p = 18315300953692143461

Fp = GF(6143872265871328074704442651454311068421530353607832481181)
a, b = Fp.random_element(), Fp.random_element()
I = Fp.gen()
lst = [50, 32, 83, 12, 49, 34, 81, 101, 46, 108, 106, 57, 105, 115, 102, 51, 67, 34, 124, 15, 125, 117, 51, 124, 38, 10, 30, 76, 125, 27, 89, 14, 50, 93, 88, 56]

n = len(lst) // 3
A = [[], [], []]

for i in range(n):
    A[0].extend(a ** i)
for i in range(n):
    A[1].extend((a ** i) * I)
for i in range(n):
    A[2].extend((a ** i)* I ^ 2)
A = matrix(ZZ, A)
B = []

for i in range(n):
    B.extend(b * (a ** i - 1) / (a - 1))
B = vector(B)
usb = vector([(x + 1) << 57 for x in lst]) - B
dsb = vector([(x) << 57 for x in lst]) - B

target = [(x + y) // 2 for x, y in zip(usb, dsb)]

A = A.stack((identity_matrix(3*n)*p)[3:])

target = vector(target)
v = cvp(A, target).list()

k = []
for i in range(0, len(v), 3):
    
    k.append(v[i] + v[i + 1] * I + v[i + 2] * (I) ^ 2)
flag = (k[0] - b) / a 
print(flag)
# print(flag.to_interger())
print(bytes.fromhex(hex(int(8054346236056770593*p^2 + 9693301027687117875*p + 4075496493969646176))[2:]))
```
### 4 Admin

---

**_chal.py_**:

```py
from os import urandom
from sys import exit
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

blksize = AES.block_size


def getintinput(msg):
    opt = input(msg)
    try:
        opt = int(opt)
    except:
        return -1
    return opt


def gethexinput(msg):
    opt = input(msg)
    opt = opt.strip()
    if all([ele in string.hexdigits for ele in opt]):
        return opt.encode()
    else:
        return b""


def givetoken(key, i):
    iv = bytes.fromhex(gethexinput("iv(hex): ").decode())
    if len(iv) != blksize:
        print("iv is invalid.")
        return None
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    curusername = b'not_admin_username_' + str(i).encode()
    enc, tag = cipher.encrypt_and_digest(pad(curusername, blksize))
    return (curusername.decode(), iv.hex(), enc.hex(), tag.hex())


def checktoken(key):
    token = bytes.fromhex(gethexinput("token(hex): ").decode())
    if len(token) % blksize != 0 or len(token) <= 2*blksize:
        print("token is invalid.")
        return None
    iv = token[:blksize]
    tag = token[-blksize:]
    enc = token[blksize:-blksize]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        dec = unpad(cipher.decrypt_and_verify(enc, tag), blksize)
    except ValueError:
        print("tag may be invalid.")
        return None
    if dec == b"admin":
        print("congrats, give you the flag.")
        flag = open('/flag.txt', 'rb').read().strip().decode()
        print(flag)
        return 1
    else:
        print("you are not admin user.")
        return 0


def banner():
    banner = [
        "#"*80,
        "AES challenge",
        "#"*80,
    ]
    print('\n'.join(banner))


def menu():
    menu = [
        "",
        "0: get token",
        "1: check admin token"
    ]
    print('\n'.join(menu))


def main():
    key = urandom(blksize)
    i = 0
    banner()
    try:
        while (True):
            menu()
            opt = getintinput("option(int): ")
            if opt == 0:
                result = givetoken(key, i)
                if result is None:
                    break
                curusername, iv, enc, tag = result
                print(f"token for {curusername} is: \n{iv + enc + tag}")
                i += 1
            elif opt == 1:
                result = checktoken(key)
                if result is None or result == 1:
                    break
            else:
                break
    except:
        print("error occured.")
        exit(1)

    print("bye")
    exit(0)


if __name__ == "__main__":
    main()
```

---


#### Tổng quan

+ Đây là một bài sử dụng AES-GCM để mã hóa, có hai chức năng chính như sau:

```py
            if opt == 0:
                result = givetoken(key, i)
```

+ khi chon 0, ta có thể gửi một iv tùy ý, và server sẻ dùng iv đó để mã hóa một chuõi `curusername = b'not_admin_username_' + str(i).encode()`

```py
            elif opt == 1:
                result = checktoken(key)
```
+ khi opt bằng 1, ta có thể gửi một token đến server, nếu giải mã nó với key của server được dec = `admin` thì sẽ trả lại cho ta flag.

#### Solution

+ Trước tiên mình cần hiểu cách hoạt động của GCM được thể hiện quan sơ đồ sau:

![image](https://github.com/user-attachments/assets/dc18c28e-97f9-4352-9426-49f6aaf6f7c4)

khi nhìn vào đầu dễ thấy `T=(((((((H∗A)+C1)∗H)+C​2)∗H)+L)∗H)+E`trong trường GF(2 ^ 128) (vì phép xor tương đương với phép cộng và hàm GHASH sử dụng với modulus = `x ^ 12 + x ^ 7 + x ^ 2 + x + 1`)

nhân phân phối ra thì ta có: `T = A ∗ H ^ 4​ + C​​ ∗ H ^ ​3​ + C ∗ H ^ 2 + L ∗ H + E`

Bây giờ nếu ta có hai tag thì dễ thấy:

+ `T1 = A ∗ H ^ 4​ + C​​1 ∗ H ^ ​3​ + C1 ∗ H ^ 2 + L ∗ H + E`
+ `T2 = A ∗ H ^ 4​ + C​​2 ∗ H ^ ​3​ + C2 ∗ H ^ 2 + L ∗ H + E`

vì nó được mã hóa bằng cùng 1 key nên bây ta chưa biết mỗi E và H. Ngoài ra trong trường hợp này A = b"00" nên ta có thể bỏ qua nó.
 
Thử cộng hai tag vào ta được:

+ `T1 + T2 = 2 * A ∗ H ^ 4​ + (C​​1 + C2) ∗ H ^ ​3​ + (C1 + C2) ∗ H ^ 2 + 2 ^ L ∗ H + 2 *  E`

do đang trong trường GF(2 ^ 128)

nên `T1 + T2 = (C​​1 + C2) ∗ H ^ ​3​ + (C1 + C2) ∗ H ^ 2` từ đó  `(C​​1 + C2) ∗ H ^ ​3​ + (C1 + C2) ∗ H ^ 2 - (T1 + T2) = 0` ta có thể giải phương trình này để tìm lại H.

Khi có H ta có thể dễ dàng thay lại vào T1 hoặc T2 để tìm lại E.

Bây giờ để có thể có bẳng mã bằng `admin` ta chỉ cần nhìn vào đây

![image](https://github.com/user-attachments/assets/eee4c82f-c44e-4ec4-bac6-15d521120e34)

dễ thấy ta chỉ cần phải bit flip nó là xong. Khi có bẳn mã ta có thể tính tag lại bằng H và E vừa tính.

#### Code

```py

from sage.all import *
from attack import *
from pwn import *
from os import urandom
from sys import exit
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

blksize = AES.block_size
s = process(["python3", "prob.py"])

# F = GF(2 ** 128, name = "i", modulus=x**128 + x**7 + x**2 + x + 1)
# P = PolynomialRing(F, name = 'x')

def bytes_to_poly(tmp):
    
    poly = [int(_) for _ in (bin(int(tmp))[2:]).zfill(128)][::-1]

    return F(poly)

def poly_to_bytes(poly):
    
    n = poly.integer_representation()

    return bytes.fromhex(hex(int(n))[2:])
    
def blocks(tmp):
    return [tmp[i:i+16] for i in range(0, len(tmp), 16)]

P = []
C = []
T = []

iv = b"00" * 16

for i in range(3):

    s.recvuntil(b"option(int): ")
    s.sendline(b"0")
    s.recvuntil(b"iv(hex):")
    
    P.append(b"not_admin_username_" + str(i).encode())
    s.sendline(b"00" * 16)
    s.recvline()
    token = bytes.fromhex(s.recvline()[:-1].decode())
    iv = token[:blksize]
    tag = token[-blksize:]
    enc = token[blksize:-blksize]
    T.append(tag)
    C.append(enc)
    
keys = recover_possible_auth_keys(b"\x00", C[0], T[0], b"\x00", C[1], T[1])

for key in keys:

    enc, tag_ = forge_tag_from_plaintext(key, b"\x00", C[2], T[2], P[2], b"\x00", pad(b"admin", 16),)

    token = iv + enc + tag_
    
    s.recvuntil(b"option(int): ")
    s.sendline(b"1")
    s.recvuntil(b"token(hex):")
    s.sendline(token.hex())

    s.interactive()
```

:v ban đầu định code tay nhưng lại chuyển qua tool viết sẵn cho dễ
https://github.com/tl2cents/AEAD-Nonce-Reuse-Attacks/blob/main/aes-gcm/aes_gcm_forgery.py
