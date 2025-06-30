
tables_of_contents
======================

### 1.  ZKP Introduction

[The_Knowledge_Complexity_Of_Interactive_Proof_Systems](https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Proof%20Systems/The_Knowledge_Complexity_Of_Interactive_Proof_Systems.pdf)

-> flag: `crypto{1085}`

### 2. Proofs of Knowledge

ZKP là một kỹ thuật để chứng minh quyền mà không cần phải bị lộ quá nhiều thông tin không cần thiết. Một ZPK sẽ có các tính chất cơ bản như sau:

+ Completeness: If the statement being proven is true, an honest verifier will be convinced by an honest prover. In other words, a correct proof will always be accepted by the verifier with high probability.

+ Soundness: If the statement is false, no dishonest prover can convince an honest verifier that it is true, except with some small probability (typically exponentially small). This ensures that a false proof has an extremely low chance of being accepted.

+ Zero-Knowledge: If the statement is true, the proof reveals no information beyond the fact that the statement is true. A verifier learns nothing other than the truth of the statement being proven. This is crucial for maintaining privacy during the proof process.

![Image description](https://cryptohack.org/static/img/zk.png)


chall

---
```py
import random
from utils import listener


FLAG = "crypto{????????????????????????}"

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2


# w,y for the relation `g^w = y mod P` we want to prove knowledge of
# w = random.randint(0,q)
# y = pow(g,w,P)
w = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5

assert (y%p) >= 1
assert pow(y, q, p) == 1

class Challenge:
    def __init__(self):
        self.before_input = "Prove to me that you know an w such that g^w = y mod p. Send me a = g^r mod p for some random r in range(q)\n"
        self.state = "CHALLENGE"

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            # Prover sends a randomly sampled `A` value from Z_p* to verifier
            self.a = msg["a"]
            if (self.a%p) < 1 or pow(self.a, q, p) != 1:
                self.exit = True
                return {"error": "Invalid value"}

            # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
            self.e = random.randint(0,2**511)
            self.state = "PROVE"
            return {"e": self.e, "message": "send me z = r + e*w mod q"}
        elif self.state == "PROVE":
            # Prover sends z = r + e*w mod q to the Verifier
            z = msg["z"]

            self.exit = True

            # Verifier checks g^z = A*h^e mod p
            if pow(g,z,p) == (self.a*pow(y,self.e,p)) % p:
                return {"flag": FLAG, "message": "You convinced me you know an `w` such that g^w = y mod p!"}
            else:
                return {"error": "something went wrong :("}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13425)

```

#### Tổng quan:

+ Bài này không có gì bởi vì mình dãd biết `w` rồi.
    ```py
                self.a = msg["a"]
                if (self.a%p) < 1 or pow(self.a, q, p) != 1:
                    self.exit = True
                    return {"error": "Invalid value"}

                # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
                self.e = random.randint(0,2**511)
                self.state = "PROVE"
                return {"e": self.e, "message": "send me z = r + e*w mod q"}
    ```
Mình cần gửi một số a thỏa mãn `a >= 1` và  `pow(self.a, q, p) != 1` nên mình đơn giản gửi `1` và nhận được `e`

+ Sau đó mình cần gửi số ư thỏa mãn `pow(g,z,p) == (self.a*pow(y,self.e,p)) % p`. Tức $g ^ z = a * (y ^ e) = a * g ^ (w * e)$. Nên mình có thể gửi z = w * e (mình đã gửi a = 1).

### Code:

```py
    
from pwn import *
from json import *

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

w = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5

s = connect("socket.cryptohack.org", 13425)

print(s.recvline())
s.sendline(dumps({"a": 1}).encode())
e = loads(s.recvline())["e"]
s.sendline(dumps({"z": e * w}).encode())
print(s.recvline())
```

### 3. Special Soundness

---

```py
import os
import random
from Crypto.Util.number import bytes_to_long
from utils import listener

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2


FLAG = b"crypto{??????????????????????}"
padded_flag = FLAG + os.urandom(q.bit_length() // 8 - len(FLAG) - 2)
flag = bytes_to_long(padded_flag)

y = pow(g,flag,p)

class Challenge:
    def __init__(self):
        self.before_input = f"I will prove to you that I know flag `w` such that y = g^w mod p.\n"
        self.state = "CHALLENGE1"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE1":
            # Prover sends a randomly sampled `A` value from Z_P* to verifier
            self.r = random.randint(0,q)
            self.a = pow(g,self.r,p)
            
            self.state = "PROVE1"
            return {"a": self.a, "y": y, "message": "send random e in range 0 <= e < 2^511"}

        elif self.state == "PROVE1":
            # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
            self.e = msg["e"]

            # Prover sends z = r + e*w mod q to the Verifier
            self.z = (self.r + self.e*flag) % q

            self.state = "CHALLENGE2"
            self.no_prompt = True # immediately send next line
            return {"z": self.z, "message": "not convinced? I'll happily do it again!"}

        elif self.state == "CHALLENGE2":
            # Prover sends a randomly sampled `A` value from Z_P* to verifier
            # self.r = random.randint(0,q) # oh no they reused the same r
            self.a2 = pow(g,self.r,p)
            
            self.state = "PROVE2"
            return {"a2": self.a2, "y": y, "message": "send random e in range 0 <= e < 2^511"}

        elif self.state == "PROVE2":
            # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
            self.e2 = msg["e"]

            # Prover sends z = r + e*w mod q to the Verifier
            self.z2 = (self.r + self.e2*flag) % q

            self.exit = True
            return {"z2": self.z2, "message": "I hope you're convinced I know the flag now. Goodbye :)"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13426)

```

---

#### Tổng quan:

Bài này khá đơn giản:

```py
"""
a, y, e, e2: choice
r
0 <= e < 2^511
a = g ^ r
z = r + e * f
z2 = r + e2 *f
a2 = g ^ r

"""
```

#### Code:

```py

import os
import random
from Crypto.Util.number import *

from pwn import *
from json import *

s = connect("socket.cryptohack.org", 13426)

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

print(s.recvline())
pub_1 = loads(s.recvline())
s.sendline(dumps({"e": 1}).encode())
z_1 = loads(s.recvline())["z"]
pub_2 = loads(s.recvline())
s.sendline(dumps({"e": 2}).encode())
z_2 = loads(s.recvline())["z2"]

flag = (z_2 - z_1) % q
print(long_to_bytes(flag))
```

### 4. Honest_Verifier_Zero_Knowledge

---

**_CHall.py_**:

```py
import os
import random
from Crypto.Util.number import bytes_to_long
from utils import listener

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

FLAG = b"crypto{?????????????????????????????}"

padded_flag = FLAG + os.urandom(q.bit_length() // 8 - len(FLAG) - 1)
flag = bytes_to_long(padded_flag)

y = pow(g,flag,p)

assert (y%p) >= 1
assert pow(y, q, p) == 1


class Challenge:
    def __init__(self):
        self.before_input = f"Send me a transcript for my given `e` proving that you know the flag `w` such that y = g^w mod p\n"
        self.state = "CHALLENGE"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            self.e = random.randint(0,2**511)
            
            self.state = "PROVE"
            return {"e": self.e, "y": y, "message": "send me your transcript"}

        elif self.state == "PROVE":
            self.a = msg["a"]
            self.z = msg["z"]

            if (self.a%p) < 1 or pow(self.a, q, p) != 1:
                self.exit = True
                return {"error": "Invalid value"}

            self.exit = True

            # Verifier checks g^z = A*h^e mod p
            if pow(g,self.z,p) == (self.a*pow(y,self.e,p)) % p:
                return {"flag": FLAG.decode(), "message": "You convinced me you know an `w` such that g^w = y mod p!"}
            else:
                return {"error": "something went wrong :("}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13427)

```

---

#### Tổng quan:

+ Vẫn tương tự như những bài trước, số `e = random.randint(0,2**511)` là một số ngẫu nhiên. Ta có json như sau :`{"e": self.e, "y": y}`  với $y = g ^ {flag}  = 2 ^ {flag} \pmod{p}$

+ Ta được nhập hai hệ số `a, z` sao cho thỏa mãn `pow(g,self.z,p) == (self.a*pow(y,self.e,p))`

#### Solution:

+ Ta có $g ^ z = a * y ^ e$ -> $2 ^ z = a * 2 ^ {w * e}$

+ Vậy dễ thấy ta có a = 1, z = w *e

#### Code:

```py

import os
import random
from Crypto.Util.number import *

from pwn import *
from json import *

s = connect("socket.cryptohack.org", 13427)

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

print(s.recvline())
pub = loads(s.recvline())

y = pub["y"]
e = pub["e"]
s.sendline(dumps({"a" : pow(pow(y, e, p), -1, p), "z" : 0}).encode())
print(s.recvline())

```

#### 5. Non_Interactive

---


**_chall.py_**:
```py
from utils import listener
from Crypto.Util.number import bytes_to_long
from hashlib import sha512

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

FLAG = b"crypto{????????????????????}"

# w,y for the relation `g^w = y mod P` we want to prove knowledge of
# w = random.randint(0,q)
# y = pow(g,w,P)
w = 0xdb968f9220c879b58b71c0b70d54ef73d31b1627868921dfc25f68b0b9495628b5a0ea35a80d6fd4f2f0e452116e125dc5e44508b1aaec89891dddf9a677ddc0
y = 0x1a1b551084ac43cc3ae2de2f89c6598a081f220010180e07eb62d0dee9c7502c1401d903018d9d7b06bff2d395c46795aa7cd8765df5ebe7414b072c8289170f0

assert (y%p) >= 1
assert pow(y, q, p) == 1


class Challenge:
    def __init__(self):
        self.before_input = f"Send me a nizk showing that you know `w` such that y = g^w mod p\n"
        self.state = "CHALLENGE"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            self.state = "PROVE"
            return {"y": y}

        elif self.state == "PROVE":
            # Prover computes (a,z) such that the transcript (a, e=hash(a), z) is an accepting transcript
            # Note that in a real protocol, you'd want to hash a lot for e. (public parameters, sesion information, etc etc)
            self.a = msg["a"]
            self.z = msg["z"]

            if (self.a%p) < 1 or pow(self.a, q, p) != 1:
                self.exit = True
                return {"error": "Invalid value"}

            # verifier computes challenge in same way as prover
            fiat_shamir_input = str(self.a).encode()
            self.e = bytes_to_long(sha512(fiat_shamir_input).digest()) % 2**511

            self.exit = True

            # Verifier checks g^z = A*h^e mod p
            if pow(g,self.z,p) == (self.a*pow(y,self.e,p)) % p:
                return {"flag": FLAG.decode(), "message": "You convinced me you know an `w` such that g^w = y mod p!"}
            else:
                return {"error": "something went wrong :("}

import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13428)

```

---

#### Tổng quan:

+ Ta được yêu cầu nhập a, z với e = hash(a) sao cho thỏa mãn $g ^z = a * y ^ e$

#### Solution:

+ Với phương trình $g ^z = a * y ^ e$ cũng viết lại tương tự như các bài trên mình có:
+ $g ^z = a * y ^ e$ -> $g ^z = a * g ^ {w * e}$
+ Vậy dễ thấy với a = 1, z = w * hash(a) sẽ thỏa mãn phương trình.

#### Code:

```py

import os
import random
from Crypto.Util.number import *
from hashlib import sha512
from pwn import *
from json import *

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

w = 0xdb968f9220c879b58b71c0b70d54ef73d31b1627868921dfc25f68b0b9495628b5a0ea35a80d6fd4f2f0e452116e125dc5e44508b1aaec89891dddf9a677ddc0
y = 0x1a1b551084ac43cc3ae2de2f89c6598a081f220010180e07eb62d0dee9c7502c1401d903018d9d7b06bff2d395c46795aa7cd8765df5ebe7414b072c8289170f0

s = connect("socket.cryptohack.org", 13428)

a = 1
fiat_shamir_input = str(a).encode()
e = bytes_to_long(sha512(fiat_shamir_input).digest()) % 2**511
z = (w * e)

print(s.recvline())
y = eval(s.recvline().decode())["y"]

s.sendline(dumps({"a": a, "z": z}).encode())
print(s.recvline())
```

### 6. Too Honest

---
__chall.py:__

```py

import os
import random
from Crypto.Util.number import bytes_to_long
from utils import listener

# RSA group (2024 bits)
# p,q are both strong primes (i.e. of the form 2x+1 for x prime)

#p = REDACTED
#q = REDACTED
#N = p * q
N = 63506177426384102189597350894327047299059434133653566917776601666605133716653510828029111986956978773016660313963972378811186153674164948861199369871734498221215139927864142313488277305751745855210473314367642273303159704466900274761354992859789827863358153922459760984397971477173435625199596782211170294424560686178858124003120741008270927463303483018910205943877584647744143454984243979284973117132536957364157878132874844783228762221620863204335896952103079109039534346621267709606103312376393511653638269034043434410564414042523141936372609708140474052147124354400977541403247799192906955295291389109531010594317

FLAG = b"crypto{???????????????????}"

g = 2

k1 = 512
k2 = 128
S = 2**k1
R = 2**(2*k2+k1)

padded_flag = FLAG + os.urandom(S.bit_length() // 8 - len(FLAG) - 2)
flag = bytes_to_long(padded_flag)

y = pow(g,-flag,N)


class Challenge:
    def __init__(self):
        self.before_input = f"I will prove to you that I know flag `w` such that y = g^-w mod N\n"
        self.state = "CHALLENGE"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            # Prover sends a randomly sampled `A` value to verifier
            self.r = random.randint(0,R)
            self.a = pow(g,self.r,N)

            self.state = "PROVE"
            return {"y": y, "a": self.a, "message": "Send a random e in range 0 <= e < 2^{k2}"}

        elif self.state == "PROVE":
            # Verifier sends a random challenge sampled from Z_{2^k2}
            self.e = msg["e"]

            # Prover sends z = r + e*w mod q to the Verifier
            self.z = (self.r + self.e*flag)

            self.exit = True 
            return {"z": self.z, "message": "I hope you're convinced I know the flag now. Goodbye :)"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13429)


```

---


#### Tổng quan

```py

padded_flag = FLAG + os.urandom(S.bit_length() // 8 - len(FLAG) - 2)
flag = bytes_to_long(padded_flag)

y = pow(g,-flag,N)
```

+ Ngay ban đầu flag sẽ được padding, và tính `y = g ^ {flag}`
+ Sau đó ta có:

```py
self.r = random.randint(0,R)
self.a = pow(g,self.r,N)

self.state = "PROVE"
return {"y": y, "a": self.a, "message": "Send a random e in range 0 <= e < 2^{k2}"}

# Verifier sends a random challenge sampled from Z_{2^k2}
self.e = msg["e"]

# Prover sends z = r + e*w mod q to the Verifier
self.z = (self.r + self.e*flag)
return {"z": self.z, "message": "I hope you're convinced I know the flag now. Goodbye :)"}
```

+ Server sẽ tạo một số ngẫu nhiên r, để tính `a = g ^ r mod N` (hai số y, a ta được biết) sau đó server yêu cầu ta gửi một số e và ta nhận được `z = r + e * flag` và kết thúc chương trình.

#### Solution:

+ Như đã nói ở trên, ta có `z = r + e * flag` và ở đây có một điều đặc biệt rằng `z` không bị chia dư, tức ta hoàn toàn có thể lấy $z = r + e * flag$ -> $flag * e = z - r$ -> $flag = (z - r) / e$ đến đây nếu bạn chưa nhận ra thì mình sẽ viết lại thành như sau cho dễ nhìn

$$flag = z / e - r / e$$

khi r << e thì ta có $-r / e = 0$ nên `flag = z // e`. Vậy bây giờ mình chỉ cần gửi một số e thật lớn là có thể lấy được flag.

#### Code:

```py

import os
import random
from Crypto.Util.number import *

from pwn import *
from json import *

N = 63506177426384102189597350894327047299059434133653566917776601666605133716653510828029111986956978773016660313963972378811186153674164948861199369871734498221215139927864142313488277305751745855210473314367642273303159704466900274761354992859789827863358153922459760984397971477173435625199596782211170294424560686178858124003120741008270927463303483018910205943877584647744143454984243979284973117132536957364157878132874844783228762221620863204335896952103079109039534346621267709606103312376393511653638269034043434410564414042523141936372609708140474052147124354400977541403247799192906955295291389109531010594317

FLAG = b"crypto{???????????????????}"

g = 2

k1 = 512
k2 = 128
S = 2**k1
R = 2**(2*k2+k1)

s = connect("socket.cryptohack.org", 13429)

print(s.recvline())
s.sendline(dumps({"e" : 2 ** 2048}).encode())

print(s.recvline())
z = eval(s.recvline())["z"]
print(long_to_bytes(z // 2 ** 2048))
```


### 7. OR Proof

---

__**chall.py:**__


```py

from enum import Flag
import random
from params import p, q, g
import os

FLAG = os.environ["FLAG"].encode()

# w,y for the relation `g^w = y mod p` we want to prove knowledge of
# w = random.randint(0,q)
# y = pow(g,w,p)
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
# w1 = REDACTED
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617
assert (y0%p) >= 1 and (y1%p) >= 1
assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1


def correctness():
    print("Correctness!")
    print(f'Prove to me that you know either w0 or w1, where g^w0 = y0 mod p, g^w1 = y1 mod p')
    # Send first round messages (a0) and (a1), for sigma protocols P1 and P2:
    a0 = int(input("a0:"))
    a1 = int(input("a1:"))

    assert (a0%p) >= 1 and (a1%p) >= 1
    assert pow(a0, q, p) == 1 and pow(a1, q, p) == 1

    # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
    s = random.randint(0,2**511-1)
    print(f'verifier sends s = {s}')

    # Prover sends (e0,z0) and (e1,z1) such that (a0,e0,z0) and (a1,e1,z1) are satisfying transcripts and e0 xor e1 == s
    e0 = int(input("e0:"))
    e1 = int(input("e1:"))
    z0 = int(input("z0:"))
    z1 = int(input("z1:"))

    # Verifier checks e0 xor e1 == s mod p
    if not e0^e1 == s:
        print("something went wrong with e0^e1 == s")
        exit()
    # Verifier checks g^z0 = A0*h^e0 mod p
    if not pow(g,z0,p) == (a0*pow(y0,e0,p)) % p:
        print("something went wrong with b=0")
        exit()
        # Verifier checks g^z1 = A1*h^e1 mod p
    if not pow(g,z1,p) == (a1*pow(y1,e1,p)) % p:
        print("something went wrong with verifying b=1 :(")
        exit()


def specialSoundness():
    # w,y for the relation `g^w = y mod p` we want to prove knowledge of
    w0 = random.randint(0,q)
    y0 = pow(g,w0,p)
    w1 = random.randint(0,q)
    y1 = pow(g,w1,p)
    assert (y0%p) >= 1 and (y1%p) >= 1
    assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1

    print(f'i will now prove knowledge of w such that either g^w=y0 or g^w=y1 mod p')
    print(f'y0 = {y0}')
    print(f'y1 = {y1}')

    # pick which one we are going to prove knowledge of
    b = random.randint(0,1)
    if b:
        w0,y0,w1,y1 = w1,y1,w0,y0

    # Special soundness!
    print("Special Soundness!")
    # honestly run transcript 0
    r0 = random.randint(0,q)
    a0 = pow(g,r0,p)

    # Simulate transcript 1
    e1 = random.randint(0,2**511-1)
    z1 = random.randint(0,q-1)
    a1 = (pow(pow(y1,e1,p),-1,p) *pow(g,z1,p)) % p

    # randomly sample s
    s = random.randint(0,2**511-1)

    # Complete transcript 0
    e0 = s^e1
    z0 = (r0 + e0*w0) % q

    ### Lets REWIND the prover back to before it received s!
    # We then recompute the e and z values with the new s, and print both transcripts
    # randomly sample s
    s2 = random.randint(0,2**511-1)

    # Complete transcript 0
    e2 = s2^e1
    z2 = (r0 + e2*w0) % q

    # if we swapped w1/w0 now we swap transcripts back
    if b:
        a0,a1,e0,e1,z0,z1 = a1,a0,e1,e0,z1,z0

    print(f'transcript 1:')
    print(f'a0 = {a0}')
    print(f'a1 = {a1}')
    print(f's = {s}')
    print(f'e0 = {e0}')
    print(f'e1 = {e1}')
    print(f'z0 = {z0}')
    print(f'z1 = {z1}')

    # update correct values in second transcript
    if b:
        e1 = e2
        z1 = z2
    else:
        e0 = e2
        z0 = z2

    print(f'transcript 2:')
    print(f'a0 = {a0}')
    print(f'a1 = {a1}')
    print(f's* = {s2}')
    print(f'e0* = {e0}')
    print(f'e1* = {e1}')
    print(f'z0* = {z0}')
    print(f'z1* = {z1}')

    wb = int(input(f'give me a witness!'))

    if not ((wb == w0) or (wb == w1)):
        print("you didn't recover the correct witness :(")
        exit()

    print("Well done! You proved extraction!")

def SHVZK():
    print(f'Finally, show me you can simulate proofs!')

    # w,y for the relation `g^w = y mod p` we want to prove knowledge of
    w0 = random.randint(0,q)
    y0 = pow(g,w0,p)
    w1 = random.randint(0,q)
    y1 = pow(g,w1,p)
    assert (y0%p) >= 1 and (y1%p) >= 1
    assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1


    s = random.randint(0,2**511-1)
    print(f'y0 = {y0}')
    print(f'y1 = {y1}')
    print(f'give me satisfying transcript for s = {s}')

    a0 = int(input(f'a0: '))
    a1 = int(input(f'a1: '))
    e0 = int(input(f'e0: '))
    e1 = int(input(f'e1: '))
    z0 = int(input(f'z0: '))
    z1 = int(input(f'z1: '))

    # Verifier checks e0 xor e1 == s mod p
    if not e0^e1 == s:
        print("something went wrong with e0^e1 == s")
        exit()
    # Verifier checks g^w0 = A0*h^e0 mod p
    if not pow(g,z0,p) == (a0*pow(y0,e0,p)) % p:
        print("something went wrong with b=0")
        exit()
        # Verifier checks g^z1 = A1*h^e1 mod p
    if not pow(g,z1,p) == (a1*pow(y1,e1,p)) % p:
        print("something went wrong with verifying b=1 :(")
        exit()


### Correctness!
# prove to the server you know either w0 or w1
correctness()

### Now do special soundness!!! 
# The server will compute two satisfying transcripts, extract one of the witnesses :)
specialSoundness()

### SHVZK
# Finally, show me you can simulate proofs!
SHVZK()

print("well done!")
print(FLAG)
```
---

#### Tổng quan:

+ Bài này được chia làm 3 phần, phần 1, 2 là phần hướng dẫn để làm phần 3. Mỗi phần sẽ như sau:

+ Phần 1: Phần này tóm lại nhứ sau.

```py
    a0 = int(input("a0:"))
    a1 = int(input("a1:"))
    s = random.randint(0,2**511-1)
    print(f'verifier sends s = {s}')
    e0 = int(input("e0:"))
    e1 = int(input("e1:"))
    z0 = int(input("z0:"))
    z1 = int(input("z1:"))

    if not e0^e1 == s:

    if not pow(g,z0,p) == (a0*pow(y0,e0,p)) % p:
   
    if not pow(g,z1,p) == (a1*pow(y1,e1,p)) % p:

```
+ Ta có s là số ngẫu nhiên, các `a0, a1, e0, e1, z0, z1` ta có thể chọn sao cho thỏa mãn `e0^e1 == s`, `pow(g,z0,p) == (a0*pow(y0,e0,p))` và `pow(g,z1,p) == (a1*pow(y1,e1,p))`.

+ Cộng với các dữ kiện khác như:

```py
# w,y for the relation `g^w = y mod p` we want to prove knowledge of
# w = random.randint(0,q)
# y = pow(g,w,p)
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
# w1 = REDACTED
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617
```

Như vậy ta có thể viết lại điều kiện như sau:

+  `e0^e1 == s`
+ `pow(g,z0,p) == (a0*pow(y0,e0,p))` -> $g ^ {z_0} = a_0 * (y_0^{e_0}) \pmod{p} \to g ^ {z_0} = a_0 * (g^{w_0 + e_0})$
+ `pow(g,z1,p) == (a1*pow(y1,e1,p))` -> $g ^ {z_1} = a_1 * (y_1^{e_1}) \pmod{p} \to g ^ {z_1} = a_1 * (g^{w_1 + e_1}) \to g ^ {z_1} = a_1 * (g^{w_1 + e_0 \oplus s})$

Khi này mình bắt đầu chọn hệ số như sau:
+ `a0 = a1 = 1`
+ `z1 = 0, a1 = 1, e1 = 0`
+ `e0 = e1 ^ s = s`
+ `z0 = w0 * e0`

+ Phần 2: Mình có tóm tắt lại dề như sau:

```py
w0, w1: random
y0, y1: random, known = g ^ w0, g ^ w1

r0: random
a0: random = g ^ r0
e1: random
z1: random
a1 = y1 ^ -e1 * g ^ z1
s: random
e0 = s ^ e1
z0 = r0 + e0 * w0
s2: random
e2 = s2 ^ e1
z2 = r0 + e2 * w0

if not e0^e1 == s:

if not pow(g,z0,p) == (a0*pow(y0,e0,p)) % p:

if not pow(g,z1,p) == (a1*pow(y1,e1,p)) % p:
```

+ về cơ bản thì những điều mình cần làm vẫn tương tự như phần trên nhưng ta cần chú ý tới:

```py
if b:
    e1 = e2
    z1 = z2
else:
    e0 = e2
    z0 = z2
```

vị trí của các phần tử sẽ bị thay đổi tùy thuộc vào b (ngẫu nhiên)

+ mình cần tìm lại `w1` hoặc `w2` khi biết tất cả các hệ số mình đã tóm tắt ở trên.
+ Do ở đây b là (0, 1) chỉ có hai trường hợp nên mình chọn luôn b = 0 để cho dễ tính toán. Khi đó mình thấy:

```py
z2 = r0 + e2 * w0
z0 = (r0 + e0*w0) % q
(z1 - z2) = w0 * (e1 - e2)
w0 = (z1 - z2) * pow(e1 - e2, -1, q) % q
```

Từ đó mình có thể tìm lại được `w0`.

+ Phần 3:

```py
    w0 = random.randint(0,q)
    y0 = pow(g,w0,p)
    w1 = random.randint(0,q)
    y1 = pow(g,w1,p)

    s = random.randint(0,2**511-1)
    print(f'y0 = {y0}')
    print(f'y1 = {y1}')
    print(f'give me satisfying transcript for s = {s}')

    a0 = int(input(f'a0: '))
    a1 = int(input(f'a1: '))
    e0 = int(input(f'e0: '))
    e1 = int(input(f'e1: '))
    z0 = int(input(f'z0: '))
    z1 = int(input(f'z1: '))

    if not e0^e1 == s:

    if not pow(g,z0,p) == (a0*pow(y0,e0,p)) % p:

    if not pow(g,z1,p) == (a1*pow(y1,e1,p)) % p:
```

+ các điều kiện của bài vẫn không đổi

    +  `e0^e1 == s`
    + `pow(g,z0,p) == (a0*pow(y0,e0,p))` -> $g ^ {z_0} = a_0 * (y_0^{e_0}) \pmod{p} \to g ^ {z_0} = a_0 * (g^{w_0 + e_0})$
    + `pow(g,z1,p) == (a1*pow(y1,e1,p))` -> $g ^ {z_1} = a_1 * (y_1^{e_1}) \pmod{p} \to g ^ {z_1} = a_1 * (g^{w_1 + e_1}) \to g ^ {z_1} = a_1 * (g^{w_1 + e_0 \oplus s})$

Mình có chọn hệ số như sau:

+ z0 = 0, a0 = 1, e0 = 0
+ e1 = s, z1 = 0, a1 = 1 / y1 ^ s

#### Code:

```py


from Crypto.Util.number import *

from pwn import *
from json import *


p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617

s = connect("archive.cryptohack.org", 11840)

# Part 1

a0 = a1 = 1

s.sendlineafter("a0:", str(a0).encode())
s.sendlineafter("a1:", str(a1).encode())
s.recvuntil(b"s = ")
secret = int(s.recvline().strip())

z1 = 0
e1 = 0
e0 = e1 ^ secret
z0 = w0 * e0
s.sendlineafter("e0:", str(e0).encode())
s.sendlineafter("e1:", str(e1).encode())
s.sendlineafter("z0:", str(z0).encode())
s.sendlineafter("z1:", str(z1).encode())

# Part 2

s.recvuntil(b"a0 = ")
a0 = int(s.recvline().strip())
s.recvuntil(b"a1 = ")
a1 = int(s.recvline().strip())
s.recvuntil(b"s = ")
secret = int(s.recvline().strip())
s.recvuntil(b"e0 = ")
e0 = int(s.recvline().strip())
s.recvuntil(b"e1 = ")
e1 = int(s.recvline().strip())
s.recvuntil(b"z0 = ")
z0 = int(s.recvline().strip())
s.recvuntil(b"z1 = ")
z1 = int(s.recvline().strip())

s.recvuntil(b"a0 = ")
a0 = int(s.recvline().strip())
s.recvuntil(b"a1 = ")
a1 = int(s.recvline().strip())
s.recvuntil(b"s* = ")
secret_ = int(s.recvline().strip())
s.recvuntil(b"e0* = ")
e0_ = int(s.recvline().strip())
s.recvuntil(b"e1* = ")
e1_ = int(s.recvline().strip())
s.recvuntil(b"z0* = ")
z0_ = int(s.recvline().strip())
s.recvuntil(b"z1* = ")
z1_ = int(s.recvline().strip())

w0 = (z1 - z1_) * pow(e1 - e1_, -1, q) % q
s.sendlineafter("witness!", str(w0).encode())

# Part 3

s.recvuntil(b"y0 = ")
y0 = int(s.recvline().strip())
s.recvuntil(b"y1 = ")
y1 = int(s.recvline().strip())
s.recvuntil(b"s = ")
secret = int(s.recvline().strip())

z0 = 0
a0 = 1
e0 = 0
e1 = secret
z1 = 0
a1 = pow(pow(y1, secret, p), -1, p)

s.sendlineafter(b"a0: ", str(a0).encode())
s.sendlineafter(b"a1: ", str(a1).encode())
s.sendlineafter(b"e0: ", str(e0).encode())
s.sendlineafter(b"e1: ", str(e1).encode())
s.sendlineafter(b"z0: ", str(z0).encode())
s.sendlineafter(b"z1: ", str(z1).encode())

s.interactive()
```

### 7, 8 hiện chưa làm được

### 10. Fischlin Transform

---

__**chall.py:**__

```py
import random
from Crypto.Util.number import bytes_to_long
from params import p, q, g
from hashlib import sha512
import json
import os

# FLAG = os.environ["FLAG"].encode()
FLAG = b"kawaikutegomen"

# kinda a random oracle
def Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1):
    ROstep = sha512(b'my')
    ROstep.update(str(a0).encode())
    ROstep.update(b'very')
    ROstep.update(str(a1).encode())
    ROstep.update(b'cool')
    ROstep.update(str(e).encode())
    ROstep.update(b'random')
    ROstep.update(str(e0).encode())
    ROstep.update(b'oracle')
    ROstep.update(str(e1).encode())
    ROstep.update(b'for')
    ROstep.update(str(z0).encode())
    ROstep.update(b'fischlin')
    ROstep.update(str(z1).encode())
    res = bytes_to_long(ROstep.digest())
    return res

def fischlin_proof(w0,w1,y0,y1,b = 0):
    if b:
        w_sim, w_b, y_sim, y_b = w0, w1, y0, y1
    else:
        w_sim, w_b, y_sim, y_b = w1, w0, y1, y0

    r_b = random.randint(0,q)
    a_b = pow(g,r_b,p)
    # Simulate transcript 1
    e_sim = random.randint(0,2**511-1)
    z_sim = random.randint(0,q)
    a_sim = (pow(pow(y_sim,e_sim,p),-1,p) *pow(g,z_sim,p)) % p
    
    # Normally you would sample for some `t` rounds, with `rho` parallel iterations
    # We simplify slightly for the purposes of this challenge. 
    # we just use `t` = 2**10, and `B` = 6, (and for this challenge we ignore parallel repititions/what happens if B is never hit)
    t = 2**10
    B = 6
    for e in range(t):
        # complete real transcript
        e_b = e^e_sim
        z_b = (r_b + e_b*w_b) % q

        # fix blinding
        if b:
            a0, a1, e0, e1, z0, z1 = a_sim, a_b, e_sim, e_b, z_sim, z_b
        else:
            a1, a0, e1, e0, z1, z0 = a_sim, a_b, e_sim, e_b, z_sim, z_b

        # if result of "random oracle" is small enough, we go with this transcript \o/
        res = Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1)
        if res < 2**(512-B):
            break  

    proof = {}
    proof["a0"] = a0
    proof["a1"] = a1
    proof["e"] = e
    proof["e0"] = e0
    proof["e1"] = e1
    proof["z0"] = z0
    proof["z1"] = z1

    return proof


def gen_round():
    w0 = random.randint(0,q)
    y0 = pow(g,w0,p)
    w1 = random.randint(0,q)
    y1 = pow(g,w1,p)
    assert (y0%p) >= 1 and (y1%p) >= 1
    assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1
    return w0, w1, y0, y1

attempts = 2**4

for round in range(64):
    print(f'round: {round}')
    print(f'I will prove knowledge of one of these dlogs, using either w0 or w1')

    for i in range(attempts):
        w0,w1,y0,y1 = gen_round()

        print(f'y0 = {y0}')
        print(f'y1 = {y1}')
        leak_witness = int(input("which witness do you want to see?"))
        if leak_witness:
            print(f'w1 = {w1}')
        else:
            print(f'w0 = {w0}')

        # choose which witness will be used for the proof
        b = int(random.randint(0,1))

        # Gives transcript (a0,a1) e (e0,e1,z0,z1) made using witness `b` where:
        # (a0,e0,z0) and (a1,e1,z1) are satisfying transcripts
        # e0 xor e1 = e 
        # RO(a0,a1,e,e0,e1,z0,z1) has `B` leading zeroes
        proof = fischlin_proof(w0,w1,y0,y1,b)

        print(f'here is your fishlin transcript')
        print(json.dumps(proof))

        trying = input("do you think you can guess my witness? (y,n)")
        if trying.lower().startswith("n"):
            continue
        else:
            break

    b_guess = int(input("which witness did the prover use?"))
    if b == b_guess:
        print("wow you distinguished my witness!")
        print(f'do it {64-round} times more for flag!')
    else:
        print("you didn't guess the right witness")
        print("skill issue + L + ratio + not able to distinguish the witness in a fischlin transform")
        exit()

print("well done, you distinguished all the witnesses!")
print(FLAG)
```

---


#### Tổng quan:

+ Hàm `Totally_a_random_oracle` về cơ bản là hàm hash sha512.
+ Hàm `fischlin_proof`:

```py
def fischlin_proof(w0,w1,y0,y1,b = 0):
    if b:
        w_sim, w_b, y_sim, y_b = w0, w1, y0, y1
    else:
        w_sim, w_b, y_sim, y_b = w1, w0, y1, y0

    r_b = random.randint(0,q)
    a_b = pow(g,r_b,p)
    # Simulate transcript 1
    e_sim = random.randint(0,2**511-1)
    z_sim = random.randint(0,q)
    a_sim = (pow(pow(y_sim,e_sim,p),-1,p) *pow(g,z_sim,p)) % p
    
    # Normally you would sample for some `t` rounds, with `rho` parallel iterations
    # We simplify slightly for the purposes of this challenge. 
    # we just use `t` = 2**10, and `B` = 6, (and for this challenge we ignore parallel repititions/what happens if B is never hit)
    t = 2**10
    B = 6
    for e in range(t):
        # complete real transcript
        e_b = e^e_sim
        z_b = (r_b + e_b*w_b) % q

        # fix blinding
        if b:
            a0, a1, e0, e1, z0, z1 = a_sim, a_b, e_sim, e_b, z_sim, z_b
        else:
            a1, a0, e1, e0, z1, z0 = a_sim, a_b, e_sim, e_b, z_sim, z_b

        # if result of "random oracle" is small enough, we go with this transcript \o/
        res = Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1)
        if res < 2**(512-B):
            break  
```

Tùy thuộc vào b mà các tham số bên trong bị đảo chỗ cho nhau, các tham số bên trong hàm `a1, a0, e, e1, e0, z1, z0` sẽ được trả lại

+ Trong hàm `main` thì ta phải hoàn thành 64 round để đoán trúng b, mỗi round ta đề có 16 lần thử để quyết định có trả lời hay không.

#### Solution:

+ Mình có thấy rằng:

```py
r_b = random.randint(0,q)
a_b = pow(g,r_b,p)
e_sim = random.randint(0,2**511-1)
z_sim = random.randint(0,q)
a_sim = (pow(pow(y_sim,e_sim,p),-1,p) *pow(g,z_sim,p)) % p
e_b = e^e_sim
z_b = (r_b + e_b*w_b) % q
```

các tham số `_b` và `sim` được tính hoàn toàn độc lập với cái còn lại (như việc tính `sim` không phụ thuộc vào bất cứ hệ số `_b` nào) nên việc

```
if b:
    a0, a1, e0, e1, z0, z1 = a_sim, a_b, e_sim, e_b, z_sim, z_b
else:
    a1, a0, e1, e0, z1, z0 = a_sim, a_b, e_sim, e_b, z_sim, z_b
```
đổi chỗ các tham số `luôn đúng` đó là lý do chính khiến việc biến đổi `a0, a1, e0, e1, z0, z1` để tìm chỗ không hợp lý là bất khả thi.

khi đó mình có nhận thấy rằng:

+ `e` không thay đổi với mọi b
+ việc sử dụng 

```py
for e in range(t):
    ...
    res = Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1)
    if res < 2**(512-B):
        break  
```
khiến e là số nhỏ nhất thỏa mãn `Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1) < 2**(512-B)`

+ Vì b chỉ có thể là 0 hoặc 1 nên mình sẽ chọn luôn b là 0 cho dễ tính.

khi b = 0, thì mình chọn nhận `w0`, khi đó mình có thể tính lại được `r_b` từ `z_b = (r_b + e_b*w_b) % q` khi đó mình thực hiện

```
for e_ in range(t):
    # complete real transcript
    e_b = e_^e_sim
    z_ = (r_b + e_b*w_b) % q
```

từ đó ta có thể tìm được các hệ số (e_, z_) thay cho các hệ số cũ là (e, z_b) khi đó mình tìm lại sao cho thỏa  mãn `Totally_a_random_oracle(a0,a1,e_,e0,e1,z0,z_)` (vì b = 0 khiến z_ tương đương với vị trí này) khi đó nếu e_ khác e thì ta có thể hoàn toàn khẳng định rằng b = 0 là sai, còn nếu `e_ = e` thì chưa chắc chắn bởi vì vẫn có thể e_ ngẫu nhiên bị trùng với e. Nên việc tính toán này sẽ tốn kha khá thời gian để chạy.

#### Code:

```py

"""

w0, w1: random

y0 = g ^ w0
y1 = g ^ w1

r_b = random
a_b = g ^ r_b


e_sim, z_sim : radom
s_sim = y_sim ^ -e_sim * g ^ z_sim
B= 6
e: known

e_b = e ^ e_sim
z_b = (r_b + e_b*w_b)

w_sim, w_b, y_sim, y_b: known
a_sim, a_b, e_sim, e_b, z_sim, z_b: known

"""

# print("ok")
from Crypto.Util.number import *

from pwn import *
from json import *
from sympy import *
from tqdm import *
from hashlib import sha512

# kinda a random oracle
def Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1):
    ROstep = sha512(b'my')
    ROstep.update(str(a0).encode())
    ROstep.update(b'very')
    ROstep.update(str(a1).encode())
    ROstep.update(b'cool')
    ROstep.update(str(e).encode())
    ROstep.update(b'random')
    ROstep.update(str(e0).encode())
    ROstep.update(b'oracle')
    ROstep.update(str(e1).encode())
    ROstep.update(b'for')
    ROstep.update(str(z0).encode())
    ROstep.update(b'fischlin')
    ROstep.update(str(z1).encode())
    res = bytes_to_long(ROstep.digest())
    return res

def fischlin_attack(w0,w1,y0,y1,b, proof):

    a0 = proof["a0"] 
    a1 = proof["a1"] 
    e  = proof["e"]  
    e0 = proof["e0"] 
    e1 = proof["e1"] 
    z0 = proof["z0"] 
    z1 = proof["z1"]
    
    if b:
        w_sim, w_b, y_sim, y_b = w0, w1, y0, y1
    else:
        w_sim, w_b, y_sim, y_b = w1, w0, y1, y0

    if b:
        a_sim, a_b, e_sim, e_b, z_sim, z_b = a0, a1, e0, e1, z0, z1
    else:
        a_sim, a_b, e_sim, e_b, z_sim, z_b = a1, a0, e1, e0, z1, z0
    
    t = 2**10
    B = 6
    r_b = (z_b - e_b*w_b) % q
    
    for e_ in range(t):
        e_b = e_^e_sim
        z_ = (r_b + e_b*w_b) % q
        
        if b:
            a0, a1, e0, e1, z0, z1 = a_sim, a_b, e_sim, e_b, z_sim, z_
        else:
            a1, a0, e1, e0, z1, z0 = a_sim, a_b, e_sim, e_b, z_sim, z_

        res = Totally_a_random_oracle(a0,a1,e_,e0,e1,z0,z1)
        if res < 2**(512-B):
            return e == e_


p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2
lst = []
# s = process(["python3", "chal.py"])
s = connect("archive.cryptohack.org", 3583)
for round in trange(64):
    for i in trange(2 ** 4):

        s.recvuntil(b"y0 = ")
        y0 = int(s.recvline().decode().strip())
        s.recvuntil(b"y1 = ")
        y1 = int(s.recvline().decode().strip())

        s.sendlineafter(b"which witness do you want to see?", b"0")

        s.recvuntil(b"w0 = ")
        w0 = int(s.recvline().decode().strip())
        s.recvline()

        proof = eval(s.recvline())

        b = fischlin_attack(w0, 0, y0, y1, 0, proof)
        if b:
            s.sendlineafter(b"do you think you can guess my witness? (y,n)", b"n")
        else:
            s.recv()
            s.sendline(b"y")
            s.recv()
            s.sendline(b"1")
            s.recvline()

            break
    if i == 15:
        print("Failed")
        s.close()
        exit()
s.interactive()

"""
crypto{fishy_fischlin_www.youtube.com/watch?v=tL6dcQEY62s}
"""
```