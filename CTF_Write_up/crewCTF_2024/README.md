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

