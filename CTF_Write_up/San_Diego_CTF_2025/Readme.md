
### San_diego_CTF_2025

#### 1. RustSA


**__main.rs__**
```rust
use std::io;
use std::convert::TryInto;

const PUBLIC_EXP: u128 = 65537;

// computes x^y mod n
fn mod_exp(x: u128, y: u128) -> u128 {
    let mut bit_length:u128 = 0;
    let mut y0:u128 = y;
    while y0 > 0 {
        y0 >>= 1;
        bit_length += 1;
    }
    let mut result:u128 = 1;
    for i in (0..bit_length).rev() {
        result = result * result;
        if (y >> i) & 1 == 1 {
            result = result * x;
        }
    }
    return result;
}

fn main() {
    let stdin = io::stdin();
    let plaintext = &mut String::new();
    println!("RustSA encryption service! Type your message below (exactly 16 characters):");
    let _ = stdin.read_line(plaintext);
    let plaintext_bytes_untrimmed = plaintext.as_bytes();
    let plaintext_bytes = &plaintext_bytes_untrimmed[0..plaintext_bytes_untrimmed.len()-1];
    if plaintext_bytes.len() != 16 {
        println!("Message not 16 characters.");
        return;
    }
    let plaintext_int = u128::from_be_bytes(plaintext_bytes.try_into().expect("Conversion Error"));
    let result = mod_exp(plaintext_int, PUBLIC_EXP);
    println!("Your ciphertext is below:");
    println!("{}", result);
}
```

**__out.txt__**

```txt
RustSA encryption service! Type your message below (exactly 16 characters):
Your ciphertext is below:
187943791592623141370643984438525124469
```

Do trong bài sử dụng kiểu dữ liệu là uint128 nên giá tri nếu vượt quá sẽ bị mod cho $2 ^ {128}$ nên ta từ đó ta có n = 2 ^ 128 và có thể dễ dang tìm phi và có được flag.

```py

from Crypto.Util.number import *
n = 1 << 128
phi = 1 << 127
c = 187943791592623141370643984438525124469
e = 65537
d = pow(e, -1, phi)
print(long_to_bytes(pow(c, d, n)))
```

#### 2. PermEG

**__PermEG.py__**

```py
from Crypto.Random import random
import numpy as np
from numpy.linalg import matrix_power

def factorial(n):
    if n == 0: return 1
    y = 1
    for i in range(1, n+1):
        y *= i
    return y

def lehmer_encode(s):
    n = len(s)
    num_factoradic = []
    remaining_indices = list(range(n))
    for x in s:
        i = remaining_indices.index(x)
        num_factoradic.append(i)
        remaining_indices.pop(i)
    num = 0
    for i, x in enumerate(num_factoradic):
        num += x * factorial(n - i - 1)
    return (num, n)

def lehmer_decode(c):
    (num, n) = c
    num_factoradic = []
    k = 0
    while factorial(k) <= num:
        k += 1
    for i in reversed(range(k)):
        x = num // factorial(i)
        num_factoradic.append(x)
        num -= x * factorial(i)
    num_factoradic = [0] * (n - k) + num_factoradic
    remaining_indices = list(range(n))
    s = []
    for x in num_factoradic:
        s.append(remaining_indices.pop(x))
    return s

def group_operation(s1, s2):
    assert(len(s1) == len(s2))
    n = len(s1)
    y = [0] * n
    for i in range(n):
        y[i] = s1[s2[i]]
    return y

def group_inv(s):
    n = len(s)
    y = [0] * n
    for i in range(n):
        y[s[i]] = i
    return y

def group_exp(s, y):
    n = len(s)
    bit_length = 0
    y0 = y
    while y0 > 0:
        y0 >>= 1
        bit_length += 1
    result = list(range(n))
    for i in reversed(range(bit_length)):
        result = group_operation(result, result)
        if (y >> i) & 1 == 1:
            result = group_operation(result, s)
    return result

def key_gen(n, q, g):
    x = random.randint(1, q-1)
    h = group_exp(g, x)
    return ((n, q, g, h), (n, q, g, x)) # public key is (n, q, g, h), secret key is (n, q, g, x)

# m is a byte string
def encrypt(pk, m):
    n, q, g, h = pk
    int_m = int.from_bytes(m, "little")
    perm_m = lehmer_decode((int_m, n))
    y = random.randint(1, q-1)
    s = group_exp(h, y)
    c1 = group_exp(g, y)
    c2 = group_operation(perm_m, s)
    return (c1, c2)

def decrypt(sk, c):
    n, q, g, x = sk
    (c1, c2) = c
    s = group_exp(c1, x)
    perm_m = group_operation(c2, group_inv(s))
    int_m, _ = lehmer_encode(perm_m)
    m = int_m.to_bytes((int_m.bit_length() + 7) // 8, "little")
    return m
```

**__encryptor.py__**

```py
from pk import pk
from PermEG import encrypt

if __name__ == "__main__":
    m = input("Enter the message you want to encrypt here: ")
    result = encrypt(pk, m.encode("utf-8"))
    with open("out.txt", "w") as f:
        f.write(str(result))
    print("Ciphertext written to out.txt")
```

ta có hai hàm giải mã và mã hóa như sau:

```py
def encrypt(pk, m):
    n, q, g, h = pk
    int_m = int.from_bytes(m, "little")
    perm_m = lehmer_decode((int_m, n))
    y = random.randint(1, q-1)
    s = group_exp(h, y)
    c1 = group_exp(g, y)
    c2 = group_operation(perm_m, s)
    return (c1, c2)

def decrypt(sk, c):
    n, q, g, x = sk
    (c1, c2) = c
    s = group_exp(c1, x)
    perm_m = group_operation(c2, group_inv(s))
    int_m, _ = lehmer_encode(perm_m)
    m = int_m.to_bytes((int_m.bit_length() + 7) // 8, "little")
    return m
```

dễ thấy để có được flag ta cần phải có được `perm_m` mà `perm_m = group_operation(c2, group_inv(s))` trong đó c2 ta đã có nên ta cần tìm lại `s`. `s` cũng được tính từ c1 và x nên chúng ta cần phải tìm lại được `x` là dễ dàng có flag, trong đó x thỏa mãn `h = group_exp(g, x)` với h, g đã có. Từ đó, ta quay trở lại thành bài toán dlog trên trường hoán vị. Bài này cũng khá giống như bài HTB2024, khi ta kiểm tra bậc của nó thì có thể thấy đây là nó có bậc là tích của nhiều số nguyên tố nhỏ nên ta có thể dùng pohlig-hellman để tìm lại x và dễ dàng có flag.

#### 3. SDES2


**__SDES2.py__**
```py
from math import gcd
import secrets

EXPONENT_BITS = 16
BASE_BITS = 32
NUM_BOXES = 8

N = 94879793147291298476721783294187445671264672494875032831129557319548520130487168324917679986052672729113562509486413401411372593283386734883795994908851074407159233933625803763510710542534207403621838561485897109991552457145707812125981258850253074177933543163534990455821426644577454934996432224034425315179

# use this to generate exponent schedule, using P as modulus for modular exponent. Not related to N
P = 270301083588606647149832441301256778567
EXPO_P = 13
SEED_BITS = 128
SEED_BYTES = SEED_BITS // 8

class RSABox:
    def __init__(self, box_key):
        assert(gcd(box_key, N) == 1)
        self.box_key = box_key
    
    def encrypt(self, pt, e):
        return (pt * pow(self.box_key, e, N)) % N

    def decrypt(self, ct, e):
        return (ct * pow(self.box_key, -e, N)) % N

class SDES2:
    # key is [p1, p2 ...], a list of integers, one for each RSABox
    def __init__(self, key):
        self.key = key
        self.boxes = [RSABox(box_key) for box_key in key]
    
    def encrypt(self, message):
        m = int.from_bytes(message, byteorder="big")

        initial_seed = (secrets.randbelow(P - 1) + 1)
        seed = initial_seed
        e = seed & ((1 << EXPONENT_BITS) - 1)
        exponent_schedule = [e]
        for _ in range(NUM_BOXES - 1):
            seed = pow(seed, EXPO_P, P)
            e = seed & ((1 << EXPONENT_BITS) - 1)
            exponent_schedule.append(e)
        for (box, e) in zip(self.boxes, exponent_schedule):
            m = box.encrypt(m, e)
        header = initial_seed.to_bytes(SEED_BYTES, byteorder="big")
        ct_bytes = m.to_bytes(m.bit_length() // 8 + 1, byteorder="big")
        return header + ct_bytes
    
    def decrypt(self, ciphertext):
        header_len = SEED_BYTES
        header_bytes = ciphertext[:header_len]
        seed = int.from_bytes(header_bytes, byteorder="big")
        e = seed & ((1 << EXPONENT_BITS) - 1)
        exponent_schedule = [e]
        for _ in range(NUM_BOXES - 1):
            seed = pow(seed, EXPO_P, P)
            e = seed & ((1 << EXPONENT_BITS) - 1)
            exponent_schedule.append(e)
        ct_bytes = ciphertext[header_len:]
        ct = int.from_bytes(ct_bytes, byteorder="big")
        for (box, e) in zip(self.boxes[::-1], exponent_schedule[::-1]):
            ct = box.decrypt(ct, e)
        message = ct.to_bytes(ct.bit_length() // 8 + 1, byteorder="big")
        return message


def generate_key():
    base_list = []
    for _ in range(NUM_BOXES):
        while True:
            base = secrets.randbits(BASE_BITS)
            if gcd(base, N) == 1:
                base_list.append(base)
                break
    return base_list
```

**__server.py__**
```py
#!/bin/python3

from SDES2 import SDES2, generate_key
import secrets
import binascii

with open("flag.txt", "r") as f:
    flag = f.read()

OPTIONS_MSG = """Select an option:
(E) Encrypt an arbitrary message (max 127 bytes)
(T) Get an encryption of the target message
(G) Guess the target message
"""
QUERY_MSG = "What is the message you want to encrypt? (max length 127 bytes)"
PROMPT_MSG = "> "
INVALID_MSG = "Invalid input."
TOO_LONG_MSG = "Message is too long."
QUOTA_DEPLETED_MSG = "Sorry, you have exhausted your message quota"
ENCRYPTED_DESCRIPTION_MSG = "Encrypted message: "
TARGET_CIPHERTEXT = """Encrypted target message: """
ASK_TARGET_MSG = "Guess what the target message is (in hex form):"

MAX_LENGTH = 127

message_quota = 20

key = generate_key()
sdes_instance = SDES2(key)

target_message = secrets.token_bytes(8)

while True:
    print(f"You are allowed to encrypt {message_quota} more messages.")
    print(OPTIONS_MSG)
    answer = input(PROMPT_MSG)
    if (answer.upper() == "E"):
        if message_quota == 0:
            print(QUOTA_DEPLETED_MSG)
            continue
        print(QUERY_MSG)
        pt_hex = input(PROMPT_MSG)
        pt = binascii.unhexlify(pt_hex)
        if len(pt) > MAX_LENGTH:
            print(TOO_LONG_MSG)
            continue
        ct = sdes_instance.encrypt(pt)
        ct_hex = binascii.hexlify(ct).decode()
        print(ENCRYPTED_DESCRIPTION_MSG)
        print(ct_hex)
        message_quota -= 1
    elif (answer.upper() == "T"):
        if message_quota == 0:
            print(QUOTA_DEPLETED_MSG)
            continue
        ct = sdes_instance.encrypt(target_message)
        ct_hex = binascii.hexlify(ct).decode()
        print(TARGET_CIPHERTEXT)
        print(ct_hex)
        message_quota -= 1
    elif (answer.upper() == "G"):
        print(ASK_TARGET_MSG)
        answer = input(PROMPT_MSG)
        target_guess = binascii.unhexlify(answer)
        if (target_guess == target_message):
            print(f"You win! Here's the flag: {flag}")
            break
        else:
            print("Sorry, that wasn't the plaintext. Better luck next time!")
            break
    else:
        print(INVALID_MSG)
        continue
```

trong bài này ta có:

+ $c = m * \prod_{i = 0}^{8}k_{i}^{e_j[i]} \pmod{N}$

Trong chương trình ta có thể thấy k được gán cố định trong mỗi phiên, e được tạo từ các seed nên ta có thể dễ dàng tìm lại `e` và chương trình cho ta nhập 19 lần để tìm kết có thể tìm lại `m` từ `c`.

để cho đơn giản thì ta gửi message mã hóa là 1 khi đó ta sẽ có 

$$
c_j = \prod_{i = 0}^{8}k_{i}^{e_j[i]} \pmod{N}
$$

giả sử ta có:

$$
tmp = \prod_{j = 0}^{19}{c_j^{t_j}} = \prod_{j = 0}^{19}{(\prod_{i = 0}^{8}k_{i}^{e_j[i]})^{t_j}} = \prod_{j = 0}^{19}{\prod_{i = 0}^{8}k_{i}^{t_j * e_j[i]}}
= \prod_{i = 0}^{8}k_{i}^{\sum_{j = 0}^{19}{t_j * e_j[i]}}
$$

ta gọi $r_i = \sum_{j = 0}^{19}{t_j * e_j[i]}$

từ đó ta có thể thấy $tmp = \prod_{i = 0}^{8}k_{i}^{r_i}$, giải sử (r_0, r_1, r_2, ..., r7) = (1, 0, 0, 0, ..., 0) thì tmp = k_0. Tương tự như vậy với (0, 1, 0, 0, ..., 0) thì ta có thể dễ dàng có được k_1.

vậy giả sử để tìm được các t_j thỏa mãn trường hợp của k1 thì ta có hệ phương trình.

$$

r_0 = 1 = t_0 * e_0[0] + t_1 * e_0[1] + ... + t_19 * e_0[19]
$$
$$
r_1 = 0 = t_0 * e_0[0] + t_1 * e_1[1] + ... + t_19 * e_1[19]
$$
$$
...
$$
$$
r_7 = 0 = t_0 * e_7[0] + t_1 * e_7[1] + ... + t_19 * e_7[19]
$$

đưa về ma trận thì ta có 
$$
\begin{bmatrix}
e_{0,0} & e_{0,1} & \cdots & e_{0,19} \\
e_{1,0} & e_{1,1} & \cdots & e_{1,19} \\
\vdots & \vdots & \ddots & \vdots \\
e_{7,0} & e_{7,1} & \cdots & e_{7,19}
\end{bmatrix}
\begin{bmatrix}
t_0 \\
t_1 \\
\vdots \\
t_{19}
\end{bmatrix}
=
\begin{bmatrix}
1 \\
0 \\
\vdots \\
0
\end{bmatrix}
$$

mình sử dụng LLL để tìm lại nghiệm nguyên thỏa mãn hệ trên rồi nhân vào lại là ta có được k1. Cứ tiếp tục tới hết là ta có thể dễ dàng có được key. Khi có được key rồi thì ta có thể dễ dàng tìm lại flag.

```py

def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)

EXPONENT_BITS = 16
BASE_BITS = 32
NUM_BOXES = 8

N = 94879793147291298476721783294187445671264672494875032831129557319548520130487168324917679986052672729113562509486413401411372593283386734883795994908851074407159233933625803763510710542534207403621838561485897109991552457145707812125981258850253074177933543163534990455821426644577454934996432224034425315179
P = 270301083588606647149832441301256778567
EXPO_P = 13
SEED_BITS = 128
SEED_BYTES = SEED_BITS // 8

import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
# context.log_level = "debug"
s = process(["python3", "server.py"])

cts = []
es = []
for i in range(19):
    s.recvuntil(b"> ")
    s.sendline(b"e")
    s.recvuntil(b"> ")
    s.sendline(b"01")
    s.recvline()
    ciphertext = bytes.fromhex(s.recvline()[:-1].decode())
    header_len = SEED_BYTES
    header_bytes = ciphertext[:header_len]
    seed = int.from_bytes(header_bytes, byteorder="big")
    e = seed & ((1 << EXPONENT_BITS) - 1)
    exponent_schedule = [e]
    for _ in range(NUM_BOXES - 1):
        seed = pow(seed, EXPO_P, P)
        e = seed & ((1 << EXPONENT_BITS) - 1)
        exponent_schedule.append(e)
    ct_bytes = ciphertext[header_len:]
    ct = int.from_bytes(ct_bytes, byteorder="big")
    es.append(exponent_schedule)
    cts.append(ct)

M = matrix(es)

ks = block_matrix([
    [M, 1/ (1 << 512)]
])

ks = ks.LLL()
keys = [0 for _ in range(8)]
for i in ks:

    t = vector(list(i[8:])) * (1 << 512)
    out = t * M

    tmp = 1
    for _, __ in zip(list(t), cts):
        tmp *= pow(__, int(_), N)
    for i in range(8):
        if out[i] != 0:
            keys[i] = pow(tmp, int(out[i]), N)
            break

s.sendline(b"t")
s.recvuntil(b"Encrypted target message:")
s.recvline()

ciphertext = bytes.fromhex(s.recvline()[:-1].decode())
header_len = SEED_BYTES
header_bytes = ciphertext[:header_len]
seed = int.from_bytes(header_bytes, byteorder="big")
e = seed & ((1 << EXPONENT_BITS) - 1)
exponent_schedule = [e]
for _ in range(NUM_BOXES - 1):
    seed = pow(seed, EXPO_P, P)
    e = seed & ((1 << EXPONENT_BITS) - 1)
    exponent_schedule.append(e)
ct_bytes = ciphertext[header_len:]
ct = int.from_bytes(ct_bytes, byteorder="big")

pt = ct
for i, (box, e) in enumerate(zip(keys, exponent_schedule)):
    pt *= pow(keys[i], -e, N)

s.sendline(b"g")
s.sendline(hex(pt % N)[2:])
s.interactive()
```