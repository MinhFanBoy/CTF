
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
