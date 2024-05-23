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

**Phân tích đề:**

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

+ Từ trên mình thấy enc_0 = xor(key, plaintetx) mà plaintext này chỉ là 32 ký tự đầu thôi trong khi ta đã biết tới 40 ký tự đầu của 
