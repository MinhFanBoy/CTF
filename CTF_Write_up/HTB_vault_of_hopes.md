Table_of_contents
=================



### 1. eXciting Outpost Recon

----

**_source.py_**

```py
from hashlib import sha256

import os

LENGTH = 32


def encrypt_data(data, k):
    data += b'\x00' * (-len(data) % LENGTH)
    encrypted = b''

    for i in range(0, len(data), LENGTH):
        chunk = data[i:i+LENGTH]

        for a, b in zip(chunk, k):
            encrypted += bytes([a ^ b])

        k = sha256(k).digest()

    return encrypted


key = os.urandom(32)

with open('plaintext.txt', 'rb') as f:
    plaintext = f.read()

assert plaintext.startswith(b'Great and Noble Leader of the Tariaki')       # have to make sure we are aptly sycophantic

with open('output.txt', 'w') as f:
    enc = encrypt_data(plaintext, key)
    f.write(enc.hex())

```

**_output.txt_**


```txt
fd94e649fc4c898297f2acd4cb6661d5b69c5bb51448687f60c7531a97a0e683072bbd92adc5a871e9ab3c188741948e20ef9afe8bcc601555c29fa6b61de710a718571c09e89027413e2d94fd3126300eff106e2e4d0d4f7dc8744827731dc6ee587a982f4599a2dec253743c02b9ae1c3847a810778a20d1dff34a2c69b11c06015a8212d242ef807edbf888f56943065d730a703e27fa3bbb2f1309835469a3e0c8ded7d676ddb663fdb6508db9599018cb4049b00a5ba1690ca205e64ddc29fd74a6969b7dead69a7341ff4f32a3f09c349d92e0b21737f26a85bfa2a10d
```


----

**Phân tích:**

Thấy flag được mã hóa bằng hàm enc như sau `enc = encrypt_data(plaintext, key)` mà key là 32 bytes ngẫu nhiên, ngoài ra ta đã biết một đoạn nhỏ của plaintext

```py

assert plaintext.startswith(b'Great and Noble Leader of the Tariaki')
```

Đi sâu hơn vào hàm mã hóa mình thấy:

+ `data += b'\x00' * (-len(data) % LENGTH)` plaintext được padding thêm các bytes `\x00` cho đến khi độ dài chia hết 32
+ `chunk = data[i:i+LENGTH]` sau đó các phần được chia thành các block có độ dài 32 bytes
+ `encrypted += bytes([a ^ b])` các plaintext được mã hóa bằng cách xor các bytes với nhau với key = sha(key)

Từ đó mình thấy hàm mã hóa có thể viết dưới dạng `enc_n = xor(key_n, plaintext) với key_0 = key, key_n = sha(key_(n-1))`

        ciphertext = enc_0 || enc_1 || ...
        
**Solution:**

+ Từ trên mình thấy enc_0 = xor(key, plaintetx) mà plaintext này chỉ là 32 ký tự đầu thôi trong khi ta đã biết tới 40 ký tự đầu của plaintext. Từ đó theo tính chất của phếp xor mình có `key_0 = xor(plaintext[:32], ciphertetx[:32])`
+ Khi đã có được key_0 thì ta có thể dễ dàng tìm lại các key_n bằng hàm hash sha_256 và thực hiện tính toán như trên để tìm lại toàn bộ plaintext.

**Code:**
```py
from pwn import xor
from hashlib import sha256
enc = "fd94e649fc4c898297f2acd4cb6661d5b69c5bb51448687f60c7531a97a0e683072bbd92adc5a871e9ab3c188741948e20ef9afe8bcc601555c29fa6b61de710a718571c09e89027413e2d94fd3126300eff106e2e4d0d4f7dc8744827731dc6ee587a982f4599a2dec253743c02b9ae1c3847a810778a20d1dff34a2c69b11c06015a8212d242ef807edbf888f56943065d730a703e27fa3bbb2f1309835469a3e0c8ded7d676ddb663fdb6508db9599018cb4049b00a5ba1690ca205e64ddc29fd74a6969b7dead69a7341ff4f32a3f09c349d92e0b21737f26a85bfa2a10d"
enc = bytes.fromhex(enc)    

leak = ("Great and Noble Leader of the Tariaki").encode()[:32]

key = xor(leak, enc[:32])

def decrypt_data(data, k):
    LENGTH = 32
    plaintext = b''

    for i in range(0, len(data), LENGTH):
        chunk = data[i:i+LENGTH]

        for a, b in zip(chunk, k):
            plaintext += bytes([a ^ b])

        k = sha256(k).digest()

    return plaintext

print(decrypt_data(enc, key))
```

### 2. Living with Elegance

----

**_server.py_**

```py
from secrets import token_bytes, randbelow
from Crypto.Util.number import bytes_to_long as b2l

class ElegantCryptosystem:
    def __init__(self):
        self.d = 16
        self.n = 256
        self.S = token_bytes(self.d)

    def noise_prod(self):
        return randbelow(2*self.n//3) - self.n//2

    def get_encryption(self, bit):
        A = token_bytes(self.d)
        b = self.punc_prod(A, self.S) % self.n
        e = self.noise_prod()
        if bit == 1:
            return A, b + e
        else:
            return A, randbelow(self.n)
    
    def punc_prod(self, x, y):
        return sum(_x * _y for _x, _y in zip(x, y))

def main():
    FLAGBIN = bin(b2l(open('flag.txt', 'rb').read()))[2:]
    crypto = ElegantCryptosystem()

    while True:
        idx = input('Specify the index of the bit you want to get an encryption for : ')
        if not idx.isnumeric():
            print('The index must be an integer.')
            continue
        idx = int(idx)
        if idx < 0 or idx >= len(FLAGBIN):
            print(f'The index must lie in the interval [0, {len(FLAGBIN)-1}]')
            continue
        
        bit = int(FLAGBIN[idx])
        A, b = crypto.get_encryption(bit)
        print('Here is your ciphertext: ')
        print(f'A = {b2l(A)}')
        print(f'b = {b}')


if __name__ == '__main__':
    main()
```


---

**Phân tích:**

```py
class ElegantCryptosystem:
    def __init__(self):
        self.d = 16
        self.n = 256
        self.S = token_bytes(self.d)

    def noise_prod(self):
        return randbelow(2*self.n//3) - self.n//2

    def get_encryption(self, bit):
        A = token_bytes(self.d)
        b = self.punc_prod(A, self.S) % self.n
        e = self.noise_prod()
        if bit == 1:
            return A, b + e
        else:
            return A, randbelow(self.n)
    
    def punc_prod(self, x, y):
        return sum(_x * _y for _x, _y in zip(x, y))
```

Đây là hàm mã hóa chính của bài này:
+ hàm `noise_prod` sẽ trả lại một giá trị random ngẫu nhiên trong một khoảng
+ hàm `punc_prod` trat lại tổng của tích các phần tử được nhập vào $\sum _{i = 0} ^{n} ({x_i} * {y_i})$
+ hàm `get_encryption` sẽ ngẫu nhiên trả lại `token_bytes(self.d), self.punc_prod(A, self.S) % self.n + self.noise_prod()` hoặc `token_bytes(self.d), randbelow(self.n)`

Server ban đầu sẽ mã hóa flag thành bit rồi yêu cầu chúng ta gửi index của flag và trả lại `A, b = crypto.get_encryption(bit)` giá trị mã hóa của bit tại vị trí ta gửi.

**solution:**

Mình thấy kết quả của hàm get_encryption như sau:
    + nếu bit = 1 và trả lại `b + e = self.punc_prod(A, self.S) % self.n + self.noise_prod() = self.punc_prod(A, self.S) % self.n + randbelow(2*self.n//3) - self.n//2` tức $ - 2 * n / 3 < b + e < n + 2 * n / 3 - n/2$
    + nếu bit = 0 thì trả lại 0 < `randbelow(self.n)` < n

Nên nếu mình gửi tơi server một index nhiều lần thì kết quả trả lại của b sẽ cho ta biết được bit tại vị trí đó:
+ nếu b < 0 hoặc b > n thì bit tại index đó là 1
+ còn lại thì ta sẽ kết luận là 0

**Code:**

```py
from pwn import *
from Crypto.Util.number import *
from tqdm import tqdm

s = connect("94.237.55.175", 33925)

def get():
    s.sendlineafter(b"Specify the index of the bit you want to get an encryption for : ", b"0")

    s.recvuntil(b"A = ")
    A = int(s.recvline()[:-1])
    s.recvuntil(b"b = ")
    b = int(s.recvline()[:-1])
    return A, b

def brute_flag():

    for i in range(15):
        A, b = get()

        if b < 0:return "1"
    
    return "0"

flag = ""

for i in tqdm(range(470)):

    flag = flag + brute_flag()
    print(flag)
```

Đây là code của mình, nó cỏ **thể** ra flag nhưng rất ngẫu nhiên và lâu nên mình có tham khảo(copy) code của anh Quốc như sau:

```py
from pwn import *
from tqdm import tqdm

conn = remote('83.136.252.165', 59718)
l = 471

flag = ['0']*l
payloads = b''

for j in range(l):
    payload = b''
    for i in range(30):
        payload += str(j).encode() + b'\n'
    payloads += payload 

conn.recvuntil(b'Specify the index of the bit you want to get an encryption for : ')
conn.sendline(payloads[:-1])

for ind in tqdm(range(l)):
    for i in range(30):
        conn.recvuntil(b'A = ')
        A = int(conn.recvline().strip().decode())
        conn.recvuntil(b'b = ')
        b = int(conn.recvline().strip().decode())
        if b < 0:
            flag[ind] = '1'
        
from Crypto.Util.number import *
bf = ''.join(flag)
bf = long_to_bytes(int(bf, 2))
print(bf)
````

Thay vì mình gửi từng lần và chờ server phản hồi từng cái sẽ rất lâu nên ta có thể gửi đồng loạt nhiều lần tới server thì thời gian sẽ nhanh hơn.

### 3. Bloom Bloom
