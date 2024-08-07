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
