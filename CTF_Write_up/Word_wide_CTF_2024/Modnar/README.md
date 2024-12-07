
### Crypto/Modnar

```py

import random1 as random
import time
from secret import flag

def get_random_array(x): 
    y = list(range(1,x))
    random.Random().shuffle(y)
    return y

my_seed = bytes(get_random_array(42))
random.seed(my_seed)
my_random_val = random.getrandbits(9999)
print(f"my seed: {my_seed.hex()}")

start = time.time()
ur_seed = bytes.fromhex(input("Enter your seed! > "))
if ur_seed == my_seed:
    print("Hey that's my seed! No copying >:(")
    exit()
if time.time() - start > 5:
    print("Too slow I've already lost interest in seeds -_- ")
    exit()

random.seed(ur_seed)
ur_random_val = random.getrandbits(9999)

print(flag) if my_random_val == ur_random_val else print("in rand we trust.")
```

#### 1. Solution

+ Bài này chúng ta có một `seed` và yêu cầu chúng ta phải tìm một `seed` khác sao cho kết quả random của hai seed trùng với nhau, nhưng hàm random của nó đã bị thay đổi so với hàm ban đầu. Chúng ta có thể thấy điểm khác nhau chủ yếu nằm ở `def seed(self, a=None, version=1):` khi này version của seed sẽ mặc định là `1` so với ban đầu là 2. Hàm sử lý seed của version `1` như sau:

```py
        if version == 1 and isinstance(a, (str, bytes)):
            a = a.decode('latin-1') if isinstance(a, bytes) else a
            x = ord(a[0]) << 7 if a else 0
            for c in map(ord, a):
                x = ((1000003 * x) ^ c) & 0xFFFFFFFFFFFFFFFF
            x ^= len(a)
            a = -2 if x == -1 else x
```

do `x = ord(a[0]) << 7 if a else 0` giá trị mặc định của x là `a[0] << 7` nên nếu giá trị ban đầu là `\x00\x80\x01` thì nó sẽ tương đương với seed `\x01` nên ta chỉ cần brute sao cho giá trị đầu tiên là `\x01` là được.

với x = `\01`
```py
x = 1 << 7
x = ((1000003 * (1 << 7)) ^ 1) & 0xFFFFFFFFFFFFFFFF
```

với x = `\00\80\01`

```py
x = 0 << 7 = 0
x = ((1000003 * (0)) ^ 0) & 0xFFFFFFFFFFFFFFFF
x = ((1000003 * (0) ^ (1 << 7))) & 0xFFFFFFFFFFFFFFFF # \x80 = 1 << 7
x = ((1000003 * (1 << 7)) ^ 1) & 0xFFFFFFFFFFFFFFFF
```

#### 2. Code

```py
from pwn import *

while True:
    # io = remote("modnar.chal.wwctf.com", "1337")
    io = process(["python3", "chall.py"])
    io.recvuntil(b"my seed: ")
    seed = bytes.fromhex(io.recvline(False).decode())
    if seed[0] != 1:
        io.close()
        continue
    myseed = b"\x00\x80" + seed[:-1]
    t = xor(seed[-1], bytes([len(seed)]), bytes([len(seed) + 2]))
    myseed = myseed + t
    io.sendline(myseed.hex().encode())
    break

io.interactive()
```