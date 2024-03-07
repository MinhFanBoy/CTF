
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


from Crypto.Util.number import *

c = 1094555114006097458981
e = 65537
n = 3367854845750390371489

p = 49450786403
q = 68105182763

assert p * q == n and isPrime(q) and isPrime(p)

d = pow(e, -1, (p - 1) * (q - 1))
print(d)
flag = pow(c, d, n)
print(long_to_bytes(88120158913819069790518253772632752253 + 741196932671749699250 ))
# BKSEC{*********}
    
# know + x = m (mod n)
know = bytes_to_long(b"BKSEC{\x00\x00\x00\x00\x00\x00\x00\x00\x00}")

print(bytes_to_long(b"a" * 16))
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
