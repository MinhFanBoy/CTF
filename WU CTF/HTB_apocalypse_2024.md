Tables of contents
------------------

### I. Crypto

### 1. Dynastic

---

**_SOURCE:_**
```py

from secret import FLAG
from random import randint

def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def encrypt(m):
    c = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha():
            ech = ch
        else:
            chi = to_identity_map(ch)
            ech = from_identity_map(chi + i)
        c += ech
    return c

with open('output.txt', 'w') as f:
    f.write('Make sure you wrap the decrypted text with the HTB flag format :-]\n')
    f.write(encrypt(FLAG))
```

**_OUTPUT:_**

```py
Make sure you wrap the decrypted text with the HTB flag format :-]
DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL

```
---

Bài này khá dễ. Tóm tắt đề như sau: Lấy lần lượt từng ký tự của txt chuyển sang số nếu m không phải là ký tự thì in nó ra, nếu nó là ký tự thì $(m - 0x41 + stt) % 26 + 0x41$. Từ đó ta chỉ cần code ngược lại là được. Thật ra là chatGPT.

```py


enc = "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"

def to_identity_map(a):
    return ord(a) + 0x41

def from_identity_map(a):
    return chr((a - 0x41) % 26 )


m = ''

for i in range(len(enc)):
    ch = enc[i]
    if not ch.isalpha():
        ech = ch
    else:
        chi = from_identity_map(ord(ch) - i)
        ech = chr(to_identity_map(chi))
        
    m += ech

print(m)
```

### 2. Makeshift

---
**_OUTPUT:_**

```py
!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB
```
---

Khi nhìn vào nó mình nhận thấy đây là mã hóa hoán đổi các vị trí của flag nên bây giờ mình cần tìm lại vị trí của nó. Thấy flag_form là HTB{} mà trong enc ta thấy chữ HTb ở cuối nên ta viết ngược nó lại rồi hoán đổi vị trí của chữ lại như ban đầu.

```py

enc: str = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
enc = enc[::-1]
for x in range(0, len(enc), 3):
    print(enc[x + 1], end= "")
    print(enc[x + 2], end= "")
    print(enc[x ], end= "")
```

### 3. PrimaryKnowledge

---

**_SOURCE:_**

```py
import math
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

m = bytes_to_long(FLAG)

n = math.prod([getPrime(1024) for _ in range(2**0)])
e = 0x10001
c = pow(m, e, n)

with open('output.txt', 'w') as f:
    f.write(f'{n = }\n')
    f.write(f'{e = }\n')
    f.write(f'{c = }\n')
```

**_OUTPUT:_**

```py
n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
e = 65537
c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215
```

---

Thấy hàm `n = math.prod([getPrime(1024) for _ in range(2**0)])` tạo ra số n là số prime nên ta hoàn toàntoàn có thể dễ dàng tìm phi và từ đó có flag.

```py


def main() -> None:

    n: int = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
    e: int = 65537
    c: int = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215

    print(long_to_bytes(pow(c, pow(e, -1, n - 1), n)))

if __name__ == "__main__":
    main()
```

### 4. Blunt

---

**_SOURCE:_**

```py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime, long_to_bytes
from hashlib import sha256

from secret import FLAG

import random


p = getPrime(32)
print(f'p = 0x{p:x}')

g = random.randint(1, p-1)
print(f'g = 0x{g:x}')

a = random.randint(1, p-1)
b = random.randint(1, p-1)

A, B = pow(g, a, p), pow(g, b, p)

print(f'A = 0x{A:x}')
print(f'B = 0x{B:x}')

C = pow(A, b, p)
assert C == pow(B, a, p)

# now use it as shared secret
hash = sha256()
hash.update(long_to_bytes(C))

key = hash.digest()[:16]
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print(f'ciphertext = {encrypted}')
```

**_OUTPUT:_**

```py

p = 0xdd6cc28d
g = 0x83e21c05
A = 0xcfabb6dd
B = 0xc4a21ba9
ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'
```

---

Đây là một bài sử dụng Diffie-Hellman ECC điển hình ta thấy số p rất nhỏ và nó cũng là số smoothprime nên ta hoàn toàn có thể dùng hàm có sẵn của thư viện để tìm discrete_log và tìm lại secret

```py


from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from sympy.ntheory.residue_ntheory import discrete_log

p = 0xdd6cc28d
g = 0x83e21c05
A = 0xcfabb6dd
B = 0xc4a21ba9
ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'

a = discrete_log(p, A, g)
secret = pow(B, a, p)

hash = sha256()
hash.update(long_to_bytes(secret))

key = hash.digest()[:16]
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'
cipher = AES.new(key, AES.MODE_CBC, iv)

print(f'{cipher.decrypt(ciphertext) = }')


```

### 5. Trà đá

---
**_SOURCE:_**

```py
import os
from secret import FLAG
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)



if __name__ == '__main__':
    KEY = os.urandom(16)
    cipher = Cipher(KEY)
    ct = cipher.encrypt(FLAG)
    with open('output.txt', 'w') as f:
        f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')

```

**_OUTPUT:_**

```py
Key : 850c1413787c389e0b34437a6828a1b2
Ciphertext : b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843
```
---

Bài này mình sử dụng chatgpt để làm vì nó khá là tốn thời gian :) Why not?

```py
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def decrypt(self, ct):
        blocks = [ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ct), self.BLOCK_SIZE//8)]
        
        pt = b''
        if self.mode == Mode.ECB:
            for block in blocks:
                pt += self.decrypt_block(block)
        elif self.mode == Mode.CBC:
            X = self.IV
            for block in blocks:
                decrypted_block = self.decrypt_block(block)
                pt += self._xor(decrypted_block, X)
                X = block
        return unpad(pt, self.BLOCK_SIZE//8)

    def decrypt_block(self, ct):
        c = b2l(ct)
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        m0 = c >> (self.BLOCK_SIZE//2)
        m1 = c & msk

        K = self.KEY
        s = (self.DELTA << 5)
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA
        
        return l2b((m0 << 32) + m1)


if __name__ == '__main__':
    with open('crypto_iced_tea/output.txt', 'r') as f:
        data = f.read().split('\n')
        KEY = bytes.fromhex(data[0].split(': ')[1])
        ct = bytes.fromhex(data[1].split(': ')[1])

    cipher = Cipher(KEY)
    pt = cipher.decrypt(ct)
    print("Decrypted Flag:", pt.decode())
```

### 6. Arranged

---
**_SOURCE:_**
```sage
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

from secret import FLAG, p, b, priv_a, priv_b

F = GF(p)
E = EllipticCurve(F, [726, b])
G = E(926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

A = G * priv_a
B = G * priv_b

print(A)
print(B)

C = priv_a * B

assert C == priv_b * A

# now use it as shared secret
secret = C[0]

hash = sha256()
hash.update(long_to_bytes(secret))

key = hash.digest()[16:32]
iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print(encrypted)
```

**_OUTPUT:_**

```py
(6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997 : 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696 : 1)
(4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734 : 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865 : 1)
b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'
```
---

Bài này yêu cầu ta phải tìm hidden_curve trong khi ta biết a và phải tìm b, p. Ta có:

+ ECC có dạng $y ^ 2 = x ^ 3 + a * x + b \pmod{p}$

nên $y ^ 2 - ( x ^ 3 + a * x) = b \pmod{p}$

Do ta có 3 điểm thuộc đường "cong" là A, B, G nên từ đó ta có thể tìm được 3 giá trị của b thỏa mãn điều kiện sau:

$$b_0 = b_1 = b_2 \pmod{p} \to b_0 - b1 = 0 = b_0 - b_2 \pmod{p}$$

Giả sử: $b_0 - b_1 = k * p$ và $b_0 - b_2 = u * p$ thì ta dễ thấy $p = GCD(b_0 - b_1, b_0 - b_2)$ sau khi có p ta có thể tìm b một cách dễ dàng:B

Còn phần sau thì mình sử dụng hàm discrete_log của sage vì đây là số smoothprime và từ đó dễ dàng có được flag.

```sage

from Crypto.Cipher import AES
from Crypto.Util.number import *
from hashlib import sha256

def main():
    a: int = 726
    G: tuple = (926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)
    A: tuple = (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997, 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696)
    B: tuple = (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734, 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865)
    enc: bytes = b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'

    b_0 = G[1] ^ 2 - (G[0] ^ 3 + a * G[0])
    b_1 = A[1] ^ 2 - (A[0] ^ 3 + a * A[0])
    b_2 = B[1] ^ 2 - (B[0] ^ 3 + a * B[0])
    p = gcd(b_0 - b_1, b_0 - b_2)
    b = b_0 % p
    
    E = EllipticCurve(GF(p), [a, b])
    G = E(G)
    A = E(A)
    B = E(B)
    print(f"{p = }")
    print(f"{b = }")
    # b = discrete_log(B, G, operation='+')
    b = 8

    secret = A * b
    secret = secret[0]

    hash = sha256()
    hash.update(long_to_bytes(int(secret)))

    key = hash.digest()[16:32]
    iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
    cipher = AES.new(key, AES.MODE_CBC, iv)

    print(f"{cipher.decrypt(enc) = }")


if __name__ == '__main__':
    main()
```


