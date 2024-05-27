Tables_of_contens
================

**Hmm:**

Mình vừa tham gia giải leak_ctf xong, trong lúc giải diễn ra mình chỉ giải được 3/7 bài. Sau khi giải kết thúc mình vẫn giải nốt vài bài còn lại dựa vào một vài gợi ý từ các anh trong clb. Sau đây là toàn bộ wu của 6/7 bài mình đã làm được (Bài cuối khó quả chịu)


### 1. realy_simple_argorithm

---

**_server.py_**

```py
from Crypto.Util.number import getPrime, bytes_to_long as btl

menu = '''(1) Encrypt Message
(2) Receive Flag
(3) Exit'''

e = 1337
size = 1024
flag = open('flag.txt', 'r').read().rstrip()

print('Welcome to the L3ak Really Simple Algorithm (RSA) Encryption Service™!')
print('Here you can encrypt your own message, or choose to receive the encrypted flag.')
print('Good luck!\n')

while True:

    p, q = getPrime(size), getPrime(size)
    n = p*q
    print(menu)

    option = int(input('Select Option: '))
    if option == 1:
        message = btl(input('Your Message: ').encode())
        enc_msg = pow(message, e, n)
        print(f'n = {n}')
        print(f'c = {enc_msg}')
    elif option == 2:
        enc_flag = pow(btl(flag.encode()), e, n)
        print(f'n = {n}')
        print(f'flag = {enc_flag}')
    elif option == 3:
        print('Goodbye!')
        exit()
    else:
        print('Invalid choice! Please try again.')


```

---

Bài này khá đơn giản khi không có nhiều hàm hay tấn công nào đặc biết.

**Phân tích:**

+ server mã hóa flag bằng RSA 1024 bit bằng hàm get_prime của thư viện, mỗi lần kết nối tới thì ta sẽ có một số n mới.

```py
while True:

    p, q = getPrime(size), getPrime(size)
    n = p*q
```

+ Khi kết nối tới server thì ta có hai lựa chọn:

  + khi option = 1, thì ta có thể gửi một đoạn msg bất kỳ và server sẽ trả lại mã hóa của nó với e, n đã được tính sẵn của server.
 
    ```py
        message = btl(input('Your Message: ').encode())
        enc_msg = pow(message, e, n)
        print(f'n = {n}')
        print(f'c = {enc_msg}')
    ```
    
  + khi option = 2, thì thì ta nhận được mã hóa của server.

    ```py
        enc_flag = pow(btl(flag.encode()), e, n)
        print(f'n = {n}')
        print(f'flag = {enc_flag}')
    ```
**Solution:**

Mình nhận thấy như sau:

khi nhận được flag mã hóa của server có dạng ${flag} ^ e = enc \pmod{n}$

mà như đã phân tích ở trên thì hàm tạo khóa nằm trong hàm while True khiến cho mỗi lần nhận được enc của server thì n đều thay đổi nhưng e không thay đổi.

Khi nhận flag nhiều lần thì ta có:

+ ${flag} ^ {65537}  = enc_1 \pmod{n_1}$
+ ${flag} ^ {65537}  = enc_2 \pmod{n_2}$
+ ${flag} ^ {65537}  = enc_3 \pmod{n_33}$



khi đó mình coi ${flag} ^ (65537) = x$ thì ta sẽ có một hệ phương trình đồng dư x  = enc_3 \pmod{n_3}$

+ $x  = enc_1 \pmod{n_1}$
+ $x  = enc_2 \pmod{n_2}$
+ $x  = enc_3 \pmod{n_3}$
  
Sử dụng CRT(định lý phần dư Trung Hoa) ta có thể tìm lại được $x = x_0 + k * N$ với $\forall k \in R$ và $x_0, x$ là nghiệm của CRT. Sau đó ta có được $x = {x_0 + k * N} = {flag} ^ e$

khi đó ta chỉ cần chạy thử k từ 0 đến khi nào ta căn e ra flag là được, nhưng như thế sẽ rất lâu vì ${flag} ^ e$ rất lớn.

Thế nên mình nhận nhiều lần enc để tạo được nhiều hệ phương trình hơn từ đó khiến cho việc CRT trở nên chính xác với ${flag} ^ e$ hơn và chỉ cần căn e lại là có flag chứ không cần phải brute để tìm k.

**Code:**

Ban đầu, code của mình chỉ nhận và gửi 1 msg mỗi lần nên khá lâu thế nên mình đã áp dụng trick từ giải trước vào để tối ưu thời gian chay.

```py

from pwn import *
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm


s = connect("193.148.168.30", 5668)
l = 15

ns = []
encs = []

payloads = b''

for j in range(l):
    payload = b''
    for i in range(50):
        payload += str(2).encode() + b'\n'
    payloads += payload 

s.sendlineafter(b"Select Option: ", payloads)

for ind in tqdm(range(l)):
    for i in range(50):
        s.recvuntil(b"n = ")
        n = int(s.recvline().strip())
        s.recvuntil(b"flag = ")
        flag = int(s.recvline().strip())


        ns.append(n)
        encs.append(flag)
        

print(long_to_bytes(int(iroot(crt(encs, ns), 1337)[0])))

```
