
Tables of contens
-----------------
## I. Kiến thức chung

- Hàm băm (hash functions) là hàm tạo với đầu vào là một dãy dài và đầu ra chỉ chứa một số lượng ký tự xác định nên nó thường được ứng dụng trong cấu  trúc dữ liệu, truyền thông tin ...(ở đây chúng ta sẽ nhìn nó dưới góc độ mật mã học)
- Nó thường được thiết kế theo kiểu hàm một chiều tức không thể giải mã được nó(cho dù biết tất cả về bản rõ thì việc đảo ngược nó vẫn gần như là bất khả thi).
- Thường được sử dụng để xác thực mã hóa, ký văn bản, kiểm tra dữ liêu... (thường được sử dụng trong RSA, ECC,...)
- Cách tần công nó gồm có 3 loại chính:
  + Pre-image attacks: tìm một đầu vào khác có cùng đầu ra với dữ liệu
  + Length extension attack: Thêm thông tin vào  văn bản đã được mã hóa bằng hàm băm
  + Collision resistance:cũng k hiểu cái này lắm kiểu như là brute force để tìm đầu vào ????
- Nói chung, hàm băm cũng có thể bị phá vỡ bởi nhiều cách tấn công nên nó cũng không thật sự an toàn lắm.

## 2. CryptoHack

### 1. Jack's Birthday Hash

---

**_TASK:_**

Today is Jack's birthday, so he has designed his own cryptographic hash as a way to celebrate.

Reading up on the key components of hash functions, he's a little worried about the security of the JACK11 hash.

Given any input data, JACK11 has been designed to produce a deterministic bit array of length 11, which is sensitive to small changes using the avalanche effect.

Using JACK11, his secret has the hash value: JACK(secret) = 01011001101.

Given no other data of the JACK11 hash algorithm, how many unique secrets would you expect to hash to have (on average) a 50% chance of a collision with Jack's secret?

---

Đọc đề ta thấy số ta cần tìm là số lượng đầu vào có thể để ta có thể brute force đầu vào của hàm băm với tỷ lệ thành cộng là 50%.

có đầu ra của hàm băm là 2 ^ 11, giả sử p(k) là xác xuất để k lần thử để có một lần chính xác vậy p(n) = 100%, $p^-(x)$ là tỷ lệ để không lần nào trong số k lần thử chính xác.
Mà $p(k) = ((n - 1)/n) ^ k$ nên tỷ lệ để có 50% thnahf công sẽ là $1 - p(x) = 1 - ((n - 1)/n) ^ k = 0.5$

```py


from math import log10

n = 2 ** 11

print(log10(0.5) / log10((n - 1)/n))
```

> 1420

### 2. Jack's Birthday Confusion

---

**_TASK:_**

The last computation has made Jack a little worried about the safety of his hash, and after doing some more research it seems there's a bigger problem.

Given no other data of the JACK11 hash algorithm, how many unique secrets would you expect to hash to have (on average) a 75% chance of a collision between two distinct secrets?

Remember, given any input data, JACK11 has been designed to produce a deterministic bit array of length 11, which is sensitive to small changes using the avalanche effect.

---


### 3. Collider

---

**_TASK:_**

Check out my document system about particle physics, where every document is uniquely referenced by hash.

Connect at socket.cryptohack.org 13389

Challenge files:
  - 13389.py

**_FILE:_**

```py
import hashlib
from utils import listener


FLAG = "crypto{???????????????????????????????????}"


class Challenge():
    def __init__(self):
        self.before_input = "Give me a document to store\n"
        self.documents = {
            "508dcc4dbe9113b15a1f971639b335bd": b"Particle physics (also known as high energy physics) is a branch of physics that studies the nature of the particles that constitute matter and radiation. Although the word particle can refer to various types of very small objects (e.g. protons, gas particles, or even household dust), particle physics usually investigates the irreducibly smallest detectable particles and the fundamental interactions necessary to explain their behaviour.",
            "cb07ff7a5f043361b698c31046b8b0ab": b"The Large Hadron Collider (LHC) is the world's largest and highest-energy particle collider and the largest machine in the world. It was built by the European Organization for Nuclear Research (CERN) between 1998 and 2008 in collaboration with over 10,000 scientists and hundreds of universities and laboratories, as well as more than 100 countries.",
        }

    def challenge(self, msg):
        if "document" not in msg:
            self.exit = True
            return {"error": "You must send a document"}

        document = bytes.fromhex(msg["document"])
        document_hash = hashlib.md5(document).hexdigest()

        if document_hash in self.documents.keys():
            self.exit = True
            if self.documents[document_hash] == document:
                return {"error": "Document already exists in system"}
            else:
                return {"error": f"Document system crash, leaking flag: {FLAG}"}

        self.documents[document_hash] = document

        if len(self.documents) > 5:
            self.exit = True
            return {"error": "Too many documents in the system"}

        return {"success": f"Document {document_hash} added to system"}


"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=13389)
```

---

hmm bài này sau khi tìm hiểu  thì mình thấy sau khi mình gửi 1 document thì nó sẽ lưu lại nên mình tìm hai đoạn string có mã hóa md5 như nhau rồi gửi nó cho sever là xong.

```py

from hashlib import md5
from pwn import *
from json import *

tmp_1 = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
tmp_2 = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"

# socket.cryptohack.org 13389

s = connect("socket.cryptohack.org",  13389)

print(s.recv().decode())

s.sendline(dumps({"document": tmp_1}).encode())

print(s.recv().decode())

s.sendline(dumps({"document": tmp_2}).encode())

print(s.recv().decode())
```

> crypto{m0re_th4n_ju5t_p1g30nh0le_pr1nc1ple}

### 4. Hash Stuffing

---

**_TASK:_**

With all the attacks on MD5 and SHA1 floating around, we thought it was time to start rolling our own hash algorithm. We've set the block size to 256 bits, so I doubt anyone will find a collision.

Connect at socket.cryptohack.org 13405

Challenge files:
  - source.py

**_FILE:_**

```py

# 2^128 collision protection!
BLOCK_SIZE = 32

# Nothing up my sleeve numbers (ref: Dual_EC_DRBG P-256 coordinates)
W = [0x6b17d1f2, 0xe12c4247, 0xf8bce6e5, 0x63a440f2, 0x77037d81, 0x2deb33a0, 0xf4a13945, 0xd898c296]
X = [0x4fe342e2, 0xfe1a7f9b, 0x8ee7eb4a, 0x7c0f9e16, 0x2bce3357, 0x6b315ece, 0xcbb64068, 0x37bf51f5]
Y = [0xc97445f4, 0x5cdef9f0, 0xd3e05e1e, 0x585fc297, 0x235b82b5, 0xbe8ff3ef, 0xca67c598, 0x52018192]
Z = [0xb28ef557, 0xba31dfcb, 0xdd21ac46, 0xe2a91e3c, 0x304f44cb, 0x87058ada, 0x2cb81515, 0x1e610046]

# Lets work with bytes instead!
W_bytes = b''.join([x.to_bytes(4,'big') for x in W])
X_bytes = b''.join([x.to_bytes(4,'big') for x in X])
Y_bytes = b''.join([x.to_bytes(4,'big') for x in Y])
Z_bytes = b''.join([x.to_bytes(4,'big') for x in Z])

def pad(data):
    padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
    return data + bytes([padding_len]*padding_len)

def blocks(data):
    return [data[i:(i+BLOCK_SIZE)] for i in range(0,len(data),BLOCK_SIZE)]

def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])

def rotate_left(data, x):
    x = x % BLOCK_SIZE
    return data[x:] + data[:x]

def rotate_right(data, x):
    x = x % BLOCK_SIZE
    return  data[-x:] + data[:-x]

def scramble_block(block):
    for _ in range(40):
        block = xor(W_bytes, block)
        block = rotate_left(block, 6)
        block = xor(X_bytes, block)
        block = rotate_right(block, 17)
    return block

def cryptohash(msg):
    initial_state = xor(Y_bytes, Z_bytes)
    msg_padded = pad(msg)
    msg_blocks = blocks(msg_padded)
    for i,b in enumerate(msg_blocks):
        mix_in = scramble_block(b)
        for _ in range(i):
            mix_in = rotate_right(mix_in, i+11)
            mix_in = xor(mix_in, X_bytes)
            mix_in = rotate_left(mix_in, i+6)
        initial_state = xor(initial_state,mix_in)
    return initial_state.hex()
```

---

Bài nãy cũng khá hay làm mình tốn một thời gian kha khá và nhờ wu trên mạng. Mình để ý rằng trước khi dc mã hóa nó phải được pad sao cho đủ 32 block nên mình chỉ cần tìm hai msg sao cho sau khi pad nó trở nên giống nhau là được từ đó ta có thể tìm ra nhiều msg khác nhau thỏa mãn bài này. (msg vẫn khác nhau nhưg pad(msg) như nhau nên nó ra cùng một cái giống nhau)

```py


from pwn import *
from json import *

# socket.cryptohack.org 13405

s = connect("socket.cryptohack.org", 13405)

print(s.recv().decode())

s.sendline(dumps({"m1": "01" * 31, "m2" : "01" * 32}).encode())

print(s.recv().decode())

```

Cách khác. Cách này mình lợi dụng hàm xor ở cuối mỗi block `initial_state = xor(initial_state,mix_in)`, khi nhìn vào đây ta thấy `enc = initial_state ^ mix_in_0 ^ mix_in_1 ^ ...` nhưng do xor có tính chất giao hoán nên ta hoàn toàn có thể `enc = initial_state ^ mix_in_0 ^ mix_in_1 ^ ... = initial_state ^ mix_in_n - 1 ^ mix_in_n - 2 ^ ...`.

do trong mỗi hàm mã hóa đều có hàm dịch bytes
```py
        for _ in range(i):
            mix_in = rotate_right(mix_in, i+11)
            mix_in = xor(mix_in, X_bytes)
            mix_in = rotate_left(mix_in, i+6)
```

nên ta có thể gửi một block có các bytes giống nhau khiến việc dịch bytes vòng trở nên vô nghĩa. Còn hàm xor mix_in thì cx không quan trọng lắm bởi vì khi trong initial_state nó cũng luỗn có số lượng giống nhau nên bị không ảnh hưởng. -> Từ đó ta có ý tưởng là gửi các block có thể khác nhau hoặc giống nhau đều được và hoán vị nó đi ta sẽ có hai msg khác nhau nhưng có chung một mã hash.

```py

from pwn import *
from json import *

# socket.cryptohack.org 13405

s = connect("socket.cryptohack.org", 13405)

print(s.recv().decode())

tmp_1 = "01" * 32
tmp_2 = "02" * 32

tmp_1, tmp_2 = tmp_1 + tmp_2, tmp_2 + tmp_1

s.sendline(dumps({"m1": tmp_1, "m2" : tmp_2}).encode())

print(s.recv().decode())
```

> Please send two hex encoded messages m1, m2 formatted in JSON:
> {"flag": "Oh no! Looks like we have some more work to do... As promised, here's your flag: crypto{Always_add_padding_even_if_its_a_whole_block!!!}"}

### 5. PriMeD5

---

**_TASK:_**

I've invented a nice simple version of HMAC authentication, hopefully it isn't vulnerable to the same problems as Merkle–Damgård construction hash functions...

Connect at socket.cryptohack.org 13388

Challenge files:
  - 13388.py


Challenge contributed by randomdude999

**_FILE:_**

```py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
from utils import listener


FLAG = "crypto{???????????????}"


def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def hash(data):
    data = pad(data, 16)
    out = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
    return out


class Challenge():
    def __init__(self):
        self.before_input = "You'll never forge my signatures!\n"
        self.key = os.urandom(16)

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            data = bytes.fromhex(msg["message"])
            if b"admin=True" in data:
                return {"error": "Unauthorized to sign message"}
            sig = hash(self.key + data)

            return {"signature": sig.hex()}

        elif msg["option"] == "get_flag":
            sent_sig = bytes.fromhex(msg["signature"])
            data = bytes.fromhex(msg["message"])
            real_sig = hash(self.key + data)

            if real_sig != sent_sig:
                return {"error": "Invalid signature"}

            if b"admin=True" in data:
                return {"flag": FLAG}
            else:
                return {"error": "Unauthorized to get flag"}

        else:
            return {"error": "Invalid option"}


"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=13388)

```
---

Bài này ban đầu mỉnh định sử dụng số giả prime để làm nhưng thấy sai sai nên quay qua đọc wu.

Ta thấy nếu hai block có 64 bytes(vì nó là block đầy đủ cần cho mỗi lần mã hóa dữ liệu) có hai mã hóa giống nhau thì ta hoàn toàn có thể pad thêm vào hai block đó mà hoàn toàn làm cho mã hash của nó giống nhau, tức:

nếu md5(A) = md5(B) thì md5(A + C) = md5(B + C)

nên bây giờ mình tìm hai đầu vào khác nhau A, B co chung đầu ra. Mình tìm thêm đoạn C để khiến A + C là prime là xong. (và sympy đã hỗ trợ săn hàm tìm số prime gần nhất rồi nên ta chỉ cần dịch bytes nó đi để tránh làm thay đổi bytes đầu và tìm là có )

```py


from array import array 
from Crypto.Util.number import *
from pwn import * 
from json import *
from sympy import nextprime


def signature(obj: dict) -> bytes:
    s.sendline(dumps(obj).encode())
    return loads(s.recvline().decode())

input1 = array('I',  [0x6165300e,0x87a79a55,0xf7c60bd0,0x34febd0b,0x6503cf04,
    0x854f709e,0xfb0fc034,0x874c9c65,0x2f94cc40,0x15a12deb,0x5c15f4a3,0x490786bb,
    0x6d658673,0xa4341f7d,0x8fd75920,0xefd18d5a])

input2 = array('I', [x^y for x,y in zip(input1, [0, 0, 0, 0, 0, 1<<10, 0, 0, 0, 0, 1<<31, 0, 0, 0, 0, 0])])

input1: bytes = input1.tobytes()
input2: bytes = input2.tobytes()

prime: int = nextprime(bytes_to_long(input1) << 512)

assert isPrime(prime)

input1 = long_to_bytes(prime)
input2 = input2 + input1[64:]
a = 1083337

s = connect("socket.cryptohack.org", 13392)
print(s.recv().decode())

sig = signature({"option": "sign", "prime": prime})["signature"]
print(signature({"option": "check", "prime": bytes_to_long(input2), "signature": sig, "a" : a}))
```

### 6. TwinKeys

---

**_Task:_**

Cryptohack's secure safe requires two keys to unlock its secret. However, Jack and Hyperreality can't remember the keys, only the start of one of them. Can you help find the lost keys to unlock the safe?

Connect at socket.cryptohack.org 13397

Challenge files:
  - 13397.py

Challenge contributed by ciphr

**_File:_**

```py

import os
import random
from Crypto.Hash import MD5
from utils import listener

KEY_START = b"CryptoHack Secure Safe"
FLAG = b"crypto{????????????????????????????}"


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


class SecureSafe:
    def __init__(self):
        self.magic1 = os.urandom(16)
        self.magic2 = os.urandom(16)
        self.keys = {}

    def insert_key(self, key):
        if len(self.keys) >= 2:
            return {"error": "All keyholes are already occupied"}
        if key in self.keys:
            return {"error": "This key is already inserted"}

        self.keys[key] = 0
        if key.startswith(KEY_START):
            self.keys[key] = 1

        return {"msg": f"Key inserted"}

    def unlock(self):
        if len(self.keys) < 2:
            return {"error": "Missing keys"}

        if sum(self.keys.values()) != 1:
            return {"error": "Invalid keys"}

        hashes = []
        for k in self.keys.keys():
            hashes.append(MD5.new(k).digest())

        # Encrypting the hashes with secure quad-grade XOR encryption
        # Using different randomized magic numbers to prevent the hashes
        # from ever being equal
        h1 = hashes[0]
        h2 = hashes[1]
        for i in range(2, 2**(random.randint(2, 10))):
            h1 = xor(self.magic1, xor(h2, xor(xor(h2, xor(h1, h2)), h2)))
            h2 = xor(xor(xor(h1, xor(xor(h2, h1), h1)), h1), self.magic2)

        assert h1 != bytes(bytearray(16))

        if h1 == h2:
            return {"msg": f"The safe clicks and the door opens. Amongst its secrets you find a flag: {FLAG}"}
        return {"error": "The keys does not match"}


class Challenge():
    def __init__(self):
        self.securesafe = SecureSafe()
        self.before_input = "Can you help find our lost keys to unlock the safe?\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}
        elif your_input['option'] == 'insert_key':
            key = bytes.fromhex(your_input["key"])
            return self.securesafe.insert_key(key)
        elif your_input['option'] == 'unlock':
            return self.securesafe.unlock()
        else:
            return {"error": "Invalid option"}


listener.start_server(port=13397)
```

---

vcl.

Sau khi tìm hiểu code mình thấy:

```py
        for i in range(2, 2**(random.randint(2, 10))):
            h1 = xor(self.magic1, xor(h2, xor(xor(h2, xor(h1, h2)), h2)))
            h2 = xor(xor(xor(h1, xor(xor(h2, h1), h1)), h1), self.magic2)
```
            
nhìn nó hơi lằng nhăng nhưng thật ra nó đơn giản như sau:

+ h1 = h1 ^ magic1
+ h2 = h ^ magic2

do tính chất của hàm xor nên ta có khi xor hai lần magic với nhau thì nó sẽ mất và chỉ còn lại h1, và số lượng vòng lặp ngẫu nhiên nên ta có 50% để h1 = h1 và h2 = h2. Từ đó chỉ cần gửi nhiều lần lên sever là được.

Bây giờ ta đến vấn đề khó hơn là làm sao cho h1 = h2 và h1 \neq b"\x00" và h1 hoặc h2 phải chứa KEY_START.

Nó khá là khó (thật ra là không thể với mình) nên mình lên mạng thìa thấy luôn một cặp h1, h2 thỏa mãn. Nên là xong luôn.

https://icewizard4902.github.io/Cryptohack/twin-keys/

```py

# https://github.com/levihackerman-102/crypto/blob/master/cryptohack/hash/twin-keys/sol.py

'''
Find md5 hash collision such that one starts with KEY_START and one doesn't
'''
# We get : 
k1: str= "43727970746f4861636b205365637572652053616665300a08de6e639eb76baa3f782925580a654ad735580c928d0e6936fecd35ebd5ac2d6bc4608b6e55239ddee23a8ae2c6bdcdf57745c78aef60b46903e9b3eb4e128ad05ab9f459839ccd8374ca53aa802edd2cba35bf081d2b7ae96e70787c391cf11bcc226565219236"
k2: str = "43727970746f4861636c205365637572652053616665300a08de6e639eb76baa3f782925580a654ad735580c928d0e6936fecd35ebd5ac2d6bc4608b6e55239ddee23a8ae2c6bdcdf57645c78aef60b46903e9b3eb4e128ad05ab9f459839ccd8374ca53aa802edd2cba35bf081d2b7ae96e70787c391cf11bcc226565219236"

from pwn import *
from json import *

def send_obj(obj: dict) -> dict:

    s.sendline(dumps(obj).encode())
    return loads(s.recvline())

s = connect("socket.cryptohack.org", 13397)

print(s.recv().decode())

print(send_obj({"option": "insert_key", "key" : k1}))
print(send_obj({"option": "insert_key", "key" : k2}))
print(send_obj({"option": "unlock"}))
```

### 7. No Difference

---

**_TASK:_**

It's easy to come across a collision for MD5, but can you find one in my custom hash function?

Connect at socket.cryptohack.org 13395

Challenge files:
  - 13395.py

**_FILE:_**

```py
from utils import listener

SBOX = [
    0xf0, 0xf3, 0xf1, 0x69, 0x45, 0xff, 0x2b, 0x4f, 0x63, 0xe1, 0xf3, 0x71, 0x44, 0x1b, 0x35, 0xc8,
    0xbe, 0xc0, 0x1a, 0x89, 0xec, 0x3e, 0x1d, 0x3a, 0xe3, 0xbe, 0xd3, 0xcf, 0x20, 0x4e, 0x56, 0x22,
    0xe4, 0x43, 0x9a, 0x6f, 0x43, 0xa9, 0x87, 0x37, 0xec, 0x2, 0x3b, 0x8a, 0x7a, 0x13, 0x7e, 0x79,
    0xcc, 0x92, 0xd7, 0xd1, 0xff, 0x5e, 0xe2, 0xb1, 0xc9, 0xd3, 0xda, 0x40, 0xfb, 0x80, 0xe6, 0x30,
    0x79, 0x1a, 0x28, 0x13, 0x1f, 0x2c, 0x73, 0xb9, 0x71, 0x9e, 0xa6, 0xd5, 0x30, 0x84, 0x9d, 0xa1,
    0x9b, 0x6d, 0xf9, 0x8a, 0x3d, 0xe9, 0x47, 0x15, 0x50, 0xb, 0xe2, 0x3d, 0x3f, 0x1, 0x59, 0x9b,
    0x85, 0xe4, 0xe5, 0x90, 0xe2, 0x2d, 0x80, 0x5e, 0x6b, 0x77, 0xa1, 0x10, 0x99, 0x72, 0x7f, 0x86,
    0x1f, 0x25, 0xa3, 0xea, 0x57, 0x5f, 0xc4, 0xc6, 0x7d, 0x7, 0x15, 0x90, 0xcb, 0x8c, 0xec, 0x11,
    0x9b, 0x59, 0x1, 0x3f, 0x3d, 0xe2, 0xb, 0x50, 0x15, 0x47, 0xe9, 0x3d, 0x8a, 0xf9, 0x6d, 0x9b,
    0xa1, 0x9d, 0x84, 0x30, 0xd5, 0xa6, 0x9e, 0x71, 0xb9, 0x73, 0x2c, 0x1f, 0x13, 0x28, 0x1a, 0x79,
    0x11, 0xec, 0x8c, 0xcb, 0x90, 0x15, 0x7, 0x7d, 0xc6, 0xc4, 0x5f, 0x57, 0xea, 0xa3, 0x25, 0x1f,
    0x86, 0x7f, 0x72, 0x99, 0x10, 0xa1, 0x77, 0x6b, 0x5e, 0x80, 0x2d, 0xe2, 0x90, 0xe5, 0xe4, 0x85,
    0x22, 0x56, 0x4e, 0x20, 0xcf, 0xd3, 0xbe, 0xe3, 0x3a, 0x1d, 0x3e, 0xec, 0x89, 0x1a, 0xc0, 0xbe,
    0xc8, 0x35, 0x1b, 0x44, 0x71, 0xf3, 0xe1, 0x63, 0x4f, 0x2b, 0xff, 0x45, 0x69, 0xf1, 0xf3, 0xf0,
    0x30, 0xe6, 0x80, 0xfb, 0x40, 0xda, 0xd3, 0xc9, 0xb1, 0xe2, 0x5e, 0xff, 0xd1, 0xd7, 0x92, 0xcc,
    0x79, 0x7e, 0x13, 0x7a, 0x8a, 0x3b, 0x2, 0xec, 0x37, 0x87, 0xa9, 0x43, 0x6f, 0x9a, 0x43, 0xe4,
]
FLAG = "crypto{??????????????????}"


# permute has the following properties:
# permute(permute(x)) = x
# permute(a) ^ permute(b) = permute(a ^ b)
def permute(block):
    result = [0 for _ in range(8)]
    for i in range(8):
        x = block[i]
        for j in range(8):
            result[j] |= (x & 1) << i
            x >>= 1
    return result


def substitute(block):
    return [SBOX[x] for x in block]


def hash(data):
    if len(data) % 4 != 0:
        return None

    state = [16, 32, 48, 80, 80, 96, 112, 128]
    for i in range(0, len(data), 4):
        block = data[i:i+4]
        state[4] ^= block[0]
        state[5] ^= block[1]
        state[6] ^= block[2]
        state[7] ^= block[3]
        state = permute(state)
        state = substitute(state)

    for _ in range(16):
        state = permute(state)
        state = substitute(state)

    output = []
    for _ in range(2):
        output += state[4:]
        state = permute(state)
        state = substitute(state)

    return bytes(output)


class Challenge:
    def __init__(self):
        self.before_input = '"The difference between treason and patriotism is only a matter of dates."\n'

    def challenge(self, msg):
        a = bytes.fromhex(msg['a'])
        b = bytes.fromhex(msg['b'])
        if len(a) % 4 != 0 or len(b) % 4 != 0:
            return {"error": "Inputs must be multiple of the block length!"}
        if a == b:
            return {"error": "Identical inputs are not allowed!"}
        if hash(a) == hash(b):
            return {"flag": f"Well done, here is the flag: {FLAG}"}
        else:
            return {"error": "The hashes don't match!"}


listener.start_server(port=13395)

```
---
