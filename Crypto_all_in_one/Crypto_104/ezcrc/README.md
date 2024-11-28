
### Crypto/ezcrc

---

**task.py**

```py
#!/usr/bin/env python3
from socketserver import BaseRequestHandler,ThreadingTCPServer
import random
import os
import string
from hashlib import sha256
import signal
import json
from flag import flag

assert len(flag) == 42 and flag.startswith(b"DubheCTF{")

with open("polys.txt","r") as f:
    polys = json.load(f)

def random_poly():
    return polys[random.randint(0,len(polys)-1)]

N = 256

BANNER = br'''
 CCCCC  RRRRRR   CCCCC       GGGG    AAA   MM    MM EEEEEEE 
CC    C RR   RR CC    C     GG  GG  AAAAA  MMM  MMM EE      
CC      RRRRRR  CC         GG      AA   AA MM MM MM EEEEE   
CC    C RR  RR  CC    C    GG   GG AAAAAAA MM    MM EE      
 CCCCC  RR   RR  CCCCC      GGGGGG AA   AA MM    MM EEEEEEE 
 '''




def crc256(msg,IN,OUT,POLY):
    crc = IN
    for b in msg:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (POLY & -(crc & 1))
    return (crc ^ OUT).to_bytes(32,'big')

def setup():
    print(BANNER)

def handle():
    # signal.alarm(120)
    # if not proof_of_work():
    #     return
    # initial
    IN = random.getrandbits(N)
    OUT = random.getrandbits(N)
    POLY = random_poly()

    for i in range(5):
        print("what do you want to do?")
        print("1.calculate crc")
        print("2.getflag")
        print("3.exit")
        try:
            choice = input()
            if choice == '1':
                msg = bytes.fromhex(input())
                crc_hex = crc256(msg,IN,OUT,POLY).hex()
                print("Here is your crc: "+crc_hex)
            elif choice == '2':
                flag_crc = crc256(flag,IN,OUT,POLY).hex()
                print("Here is your flag: "+flag_crc)
            else:
                return
        except:
            print("error")
            pass

handle()
```

---

#### 1. Tổng quan 

+ Với hàm mã hóa chính là `crc256`, đây là một hàm gần giống như tính hash của sha256. Thường thì được dùng để kiểm tra độ dài toàn vẹn của thông điệp.

+ Có hai lựa chọn chính:
    + với option `1` ta có thể gửi một `msg` bất kỳ và ta có `crc256(msg)`
    + còn option `2` thì chúng ta có thể nhận được `crc256(flag)`

#### 2. Solution

+ Chúng ta có hàm `crc256` như sau:

```py
def crc256(msg,IN,OUT,POLY):
    crc = IN
    for b in msg:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (POLY & -(crc & 1))
    return (crc ^ OUT).to_bytes(32,'big')
```

ta có thể đưa nó về dạng biểu thức toán học như sau:

$CRC(M) = Mx^n + F + (F + {IN})x^b + {OUT} \pmod{{POLY}}$

trong đó:

    + M là msg đầu vào
    + F là giá trị cơ bản của trường, ở đây là $2 ^ {256} - 1$
    + IN, OUT, Poly là giá trị hàm nhập vào
    + Lưu ý ràng ở đây tất cả đều được đưa vào trường GF(2, 256) với modul = Poly nên các đầu vào sẽ bị nghịch đảo các bit.
    + n = bậc của trường = 256
    + b = độ dài bit của msg, ở đây là (42 * 8) do flag có 42 bytes.


trong phương trình trên ta đã biết M, C, F và POLY, IN, OUT là cố định nên chúng ta có:

$C_1 + M_1 * x ^ n + F + F * x ^ b =  {I}x^b + {O} \pmod{P}$

$C_2 + M_2 * x ^ n + F + F * x ^ b =  {I}x^b + {O} \pmod{P}$

nên $C_1 + C_2 + (M_1 + M_2) * x ^ b = 0$

$\to GCD(C_1 + C_2 + (M_1 + M_2) * x ^ b, C_3 + C_4 + (M_3 + M_4) * x ^ b) = P$

thay lại P vào một phương trình bất kỳ ta có:

$C_1 + C_{flag} + (M_1 + {flag}) * x ^ b = 0 \pmod{P}$

do ta chỉ còn mỗi flag chưa biết nên ta hoàn toàn có thể tìm lại flag một cách dễ dàng. Tuy nhiên, do đây đang tròn trường GF(2, 256) nên flasg cũng bị cắt đi chỉ còn có thể tìm lại 32 ký tự nhưng ta cũng thấy flag = DubheCTF{ + ? * 32 + } nên ta có thể tìm lại đoạn chưa biết bằng cách pad thêm phần đã biết vào như sau:

$C_1 + C_{flag} + (M_1 + {flag * 256 + pad}) * x ^ b = 0 \pmod{P}$

+ Ngoài ra chúng ta có thể thấy nếu m = 1 thì ta sẽ có `crc256(m) = Poly` từ đó có thể recover lại nhanh hơn.

#### 3. Code

```py


from pwn import *
from Crypto.Util.number import *
from sage.all import *

# s = process(["python3", "task.py"])
# s = connect("0.0.0.0", 1338)
# context.log_level = "debug"

payload = [
    b"\x00" * 42,
    b"\x00" * 41 + b"\x80",
    b"\x00" * 41 + b"\x01",
    b"DubheCTF{" + b"\x00" * 32 + b"}"
]

s = process(["python3", "task.py"])
out = []
for i in range(4):
    s.recvuntil(b'3.exit\n')
    s.sendline(b"1")
    s.sendline(payload[i].hex())
    out.append(bytes.fromhex(s.recvline().split(b":")[1].strip().decode()))

s.recvuntil(b'3.exit\n')
s.sendline(b"2")
c = bytes.fromhex(s.recvline().split(b":")[1].strip().decode())
out = [bytes_to_long(i) for i in out]
c = bytes_to_long(c)
payload = [int.from_bytes(i, 'little') for i in payload]

FF = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
F = GF(2)["x"]
x = F.gen()
def i2p(p):
    return F(Integer(p).bits())

def p2i(p):
    return Integer(p.list(), 2)

def rev(p, n):
    p = (p.list() + [0] * n)[:n]
    return F(p[::-1])

t1 = rev(i2p(out[0]), 256) -rev(i2p(payload[0]), 42 * 8) * (x ** 256) - rev(i2p(FF), 256) *(1 + x ** (42 * 8))
t2 = rev(i2p(out[1]), 256) -rev(i2p(payload[1]), 42 * 8) * (x ** 256) - rev(i2p(FF), 256) *(1 + x ** (42 * 8))
t3 = rev(i2p(out[2]), 256) -rev(i2p(payload[2]), 42 * 8) * (x ** 256) - rev(i2p(FF), 256) *(1 + x ** (42 * 8))
t4 = rev(i2p(out[3]), 256) -rev(i2p(payload[3]), 42 * 8) * (x ** 256) - rev(i2p(FF), 256) *(1 + x ** (42 * 8))

G1 = gcd(t1 - t2, t1 - t3)
G2 = gcd(t1 - t2, t1 - t4)
print(G1 == G2)
K = GF(2**256, "a",modulus = G1)

def int2poly(n, padlen=256):
    return K(ZZ(n).digits(base=2, padto=padlen)[::-1])

def poly2int(p, padlen=256):
    L = p.list()
    L += [0] * (padlen - len(L))
    return int(ZZ(L[::-1], base=2))

tmp = K(((int2poly(out[3]) - int2poly(c)) / K(x ** (256 + 8))) % G1)
print(long_to_bytes(poly2int(tmp, 256))[::-1])
```
