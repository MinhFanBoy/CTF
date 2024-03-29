
Table_of_contens
================


## Crypto_Hack_RSA

Mình viết bài này để làm nốt 3 bài còn thiếu hồi KCSC tranning( mặc dù bây giờ vẫn còn đang trainning :l)

Mình cx k làm được bài nào trong những bài này mà đề tìm hiểu lại wu khác mong khi khác quay lại có thể tự làm được những bài như này.

### 1. Let's Decrypt

---

**_source:_**

```py
#!/usr/bin/env python3

import re
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener
from pkcs1 import emsa_pkcs1_v15
# from params import N, E, D

FLAG = "crypto{?????????????????????????????????}"

MSG = 'We are hyperreality and Jack and we own CryptoHack.org'
DIGEST = emsa_pkcs1_v15.encode(MSG.encode(), 256)
SIGNATURE = pow(bytes_to_long(DIGEST), D, N)


class Challenge():
    def __init__(self):
        self.before_input = "This server validates domain ownership with RSA signatures. Present your message and public key, and if the signature matches ours, you must own the domain.\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_signature':
            return {
                "N": hex(N),
                "e": hex(E),
                "signature": hex(SIGNATURE)
            }

        elif your_input['option'] == 'verify':
            msg = your_input['msg']
            n = int(your_input['N'], 16)
            e = int(your_input['e'], 16)

            digest = emsa_pkcs1_v15.encode(msg.encode(), 256)
            calculated_digest = pow(SIGNATURE, e, n)

            if bytes_to_long(digest) == calculated_digest:
                r = re.match(r'^I am Mallory.*own CryptoHack.org$', msg)
                if r:
                    return {"msg": f"Congratulations, here's a secret: {FLAG}"}
                else:
                    return {"msg": f"Ownership verified."}
            else:
                return {"error": "Invalid signature"}

        else:
            return {"error": "Invalid option"}


listener.start_server(port=13391)
```

---

Bài này chủ yếu yêu cầu như sau:
+ emsa_pkcs1_v15.encode(msg.encode(), 256) = pow(SIGNATURE, e, n)
+ re.match(r'^I am Mallory.*own CryptoHack.org$', msg)

Tức là nội dung mình gửi đi phải thỏa mãn có dòng chữ kia và bằng với sig ^ e. Nhưng ở đây e và N trong phép tính là của mình gửi đi nên mình hoàn toàn có thể vượt qua được nó.

có `msg = I am Mallory.*own CryptoHack.org` < `MSG = We are hyperreality and Jack and we own CryptoHack.org`, msg < sig tức:

$$msg = sig - (sig - msg)$$

$msg = sig \pmod{(sig - msg)}$ mà server tính $msg = {sig} ^ e  \pmod{N}$

:v và thế là ta dễ thấy khi e = 1, N = sig - msg thì luôn đúng nên ta có thể hoàn thành bài toán 900 sâu một cách dễ dàng.

```py


from pwn import *
from json import *
from Crypto.Util.number import *
from pkcs1 import emsa_pkcs1_v15

s = connect("socket.cryptohack.org", 13391)
print(s.recvline())
s.sendline(dumps({
    "option": "get_signature",
}).encode())

sig = int(loads(s.recvline())["signature"], 16)
txt = b'I am Malloryown CryptoHack.org'
dig = emsa_pkcs1_v15.encode(txt, 256)

s.sendline(dumps({
    "option": "verify",
    "N": hex(sig - bytes_to_long(dig))[2:],
    "e": hex(1)[2:],
    "msg": txt.decode()
}).encode())

print(s.recvline())

```

### 2. Let decrypt again

---

**_Source:_**

```py
#!/usr/bin/env python3

import hashlib
import re
import secrets
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse, isPrime
from pkcs1 import emsa_pkcs1_v15
from utils import listener
# from params import N, E, D

FLAG = b"crypto{????????????????????????????????????}"

BIT_LENGTH = 768

MSG = b'We are hyperreality and Jack and we own CryptoHack.org'
DIGEST = emsa_pkcs1_v15.encode(MSG, BIT_LENGTH // 8)
SIGNATURE = pow(bytes_to_long(DIGEST), D, N)
BTC_PAT = re.compile("^Please send all my money to ([1-9A-HJ-NP-Za-km-z]+)$")


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def btc_check(msg):
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    addr = BTC_PAT.match(msg)
    if not addr:
        return False
    addr = addr.group(1)
    raw = b"\0" * (len(addr) - len(addr.lstrip(alpha[0])))
    res = 0
    for c in addr:
        res *= 58
        res += alpha.index(c)
    raw += long_to_bytes(res)

    if len(raw) != 25:
        return False
    if raw[0] not in [0, 5]:
        return False
    return raw[-4:] == hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]


PATTERNS = [
    re.compile(r"^This is a test(.*)for a fake signature.$").match,
    re.compile(r"^My name is ([a-zA-Z\s]+) and I own CryptoHack.org$").match,
    btc_check
]


class Challenge():
    def __init__(self):
        self.shares = [secrets.token_bytes(len(FLAG))
                       for _ in range(len(PATTERNS) - 1)]
        last_share = FLAG
        for s in self.shares:
            last_share = xor(last_share, s)
        self.shares.append(last_share)

        self.pubkey = None
        self.suffix = None

        self.before_input = "This server validates statements we make for you. Present your messages and public key, and if the signature matches ours, you must undoubtably be us. Just do it multiple times to make sure...\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_signature':
            return {
                "N": hex(N),
                "E": hex(E),
                "signature": hex(SIGNATURE)
            }

        elif your_input['option'] == 'set_pubkey':
            if self.pubkey is None:
                pubkey = int(your_input['pubkey'], 16)
                if isPrime(pubkey):
                    return {"error": "Everyone knows RSA keys are not primes..."}
                self.pubkey = pubkey
                self.suffix = secrets.token_hex(32)

                return {"status": "ok", "suffix": self.suffix}
            return {"error": "I already had one"}

        elif your_input['option'] == 'claim':
            if self.pubkey is None:
                return {"error": "I need your modulus first, please"}

            msg = your_input['msg']
            n = self.pubkey
            e = int(your_input['e'], 16)
            index = your_input['index']
            if not (0 <= index < len(PATTERNS)):
                return {"error": "invalid index"}

            if not msg.endswith(self.suffix):
                return {"error": "Invalid message"}

            digest = emsa_pkcs1_v15.encode(msg.encode(), BIT_LENGTH // 8)
            calculated_digest = pow(SIGNATURE, e, n)

            if bytes_to_long(digest) == calculated_digest:
                r = PATTERNS[index](msg[:-len(self.suffix)])
                if r:
                    return {"msg": "Congratulations, here's a secret", "secret": self.shares[index].hex()}
                else:
                    return {"msg": "Ownership verified."}
            else:
                return {"error": "Invalid signature"}

        else:
            return {"error": "Invalid option"}


listener.start_server(port=13394)
```
---

Phân tích đề kỹ hơn ta thấy :

```py
msg1 = "This is a test for a fake signature." + suffix
msg2 = "My name is Minh and I own CryptoHack.org" + suffix
msg3 = "Please send all my money to " + bitcoin_address + suffix
```

Ta có thể gửi e và N để server tính theo số chúng ta gửi, sao cho:

$sig ^ {e_1} = msg_1$

$sig ^ {e_2} = msg_2$

$sig ^ {e_3} = msg_3$

Nên ta buộc phải tính discrete_log nên mình gửi một số N là smooth prime để thuận tiện cho việc tính. Sau khi tính xong ta chỉ cần gửi lại là xong.

Mỗi tội là code này hơi bruhhhh nên tỉnh thoảng bị lỗi không chạy được.

```py

from pwn import *
from json import *
from Crypto.Util.number import *
# from bitcoin import random_key, privtopub, pubtoaddr
from pkcs1 import emsa_pkcs1_v15

# socket.cryptohack.org 13394
s = connect("socket.cryptohack.org", 13394)
s.recvline()

N = getPrime(13) ** 60

s.sendline(dumps({
    "option": "get_signature",
}).encode())

public = loads(s.recvline().decode())
sig = Mod(int(public["signature"], 16), N)

s.sendline(dumps({
    "option": "set_pubkey",
    "pubkey": hex(N)[2:]
}).encode())

suffix = loads(s.recvline().decode())["suffix"]
print(f"> suffix: {suffix}")
# bitcoin_address = pubtoaddr(privtopub(random_key()))
bitcoin_address = "1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX"
msg1 = "This is a test for a fake signature." + suffix
msg2 = "My name is Minh and I own CryptoHack.org" + suffix
msg3 = "Please send all my money to " + bitcoin_address + suffix



m1 = bytes_to_long(emsa_pkcs1_v15.encode(msg1.encode(), 768 // 8))
m2 = bytes_to_long(emsa_pkcs1_v15.encode(msg2.encode(), 768 // 8))
m3 = bytes_to_long(emsa_pkcs1_v15.encode(msg3.encode(), 768 // 8))

print(f"> set up done.")

e_1 = int(discrete_log(Mod(m1, N), sig))
e_2 = int(discrete_log(Mod(m2, N), sig))
e_3 = int(discrete_log(Mod(m3, N), sig))

print(f"> Now: discrete_log done.")
print(f"> Start connect to server.")
s.sendline(dumps({
    "option": "claim",
    "msg": msg1,
    "index": int(0),
    "e": hex(e_1)[2:]}).encode())

secret1 = loads(s.recvline().decode())["secret"]

s.sendline(dumps({
    "option": "claim",
    "msg": msg2,
    "index": int(1),
    "e": hex(e_2)[2:]}).encode())

secret2 = loads(s.recvline().decode())["secret"]

s.sendline(dumps({
    "option": "claim",
    "msg": msg3,
    "index": int(2),
    "e": hex(e_3)[2:]}).encode())

secret3 = loads(s.recvline().decode())["secret"]

print(f"> Flag:")
print(xor(bytes.fromhex(secret1), bytes.fromhex(secret2), bytes.fromhex(secret3)))
```

### 3 Vote for Pedro

---

**_Source:_**
```py
#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener

FLAG = "crypto{????????????????????}"


class Challenge():
    def __init__(self):
        self.before_input = "Place your vote. Pedro offers a reward to anyone who votes for him!\n"

    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'vote':
            vote = int(your_input['vote'], 16)
            verified_vote = long_to_bytes(pow(vote, ALICE_E, ALICE_N))

            # remove padding
            vote = verified_vote.split(b'\00')[-1]

            if vote == b'VOTE FOR PEDRO':
                return {"flag": FLAG}
            else:
                return {"error": "You should have voted for Pedro"}

        else:
            return {"error": "Invalid option"}


listener.start_server(port=13375)
```

**_output:_**
```py
N = 22266616657574989868109324252160663470925207690694094953312891282341426880506924648525181014287214350136557941201445475540830225059514652125310445352175047408966028497316806142156338927162621004774769949534239479839334209147097793526879762417526445739552772039876568156469224491682030314994880247983332964121759307658270083947005466578077153185206199759569902810832114058818478518470715726064960617482910172035743003538122402440142861494899725720505181663738931151677884218457824676140190841393217857683627886497104915390385283364971133316672332846071665082777884028170668140862010444247560019193505999704028222347577

e = 3

```

---

Việc mình cần làm trong bài này khá đơn giản chỉ cần gửi đi một thông điệp msg sao cho:
+ $msg ^ e \pmod{N}$ có chứa `VOTE FOR PEDRO`

Minh dễ thấy nếu $msg ^ e < N$ thì phép mod trở nên vô nghĩa từ đó mình chỉ cần tìm `msg ^ e = VOTE FOR PEDRO `

do đề bài tách phần `msg ^ e` bằng bytes `\x00` nên mình đệm thêm thông tin như sau `"\001\00VOTE FOR PEDRO"` mà nó vẫn đúng.

dễ thấy ta luôn có thể tìm được :

$$m ^ e = h * (256 ^ {len(msg)}) + msg$$

Từ đó ta có $m ^ e = msg \pmod{256 ^ {16}}$

và để tính cái này thì mình sử dụng hàm của sage :vvv

từ đó tính ra được m và gửi cho server -> ez

```py


from Crypto.Util.number import *
from pwn import *
from json import *

txt = bytes_to_long(b"\001\00VOTE FOR PEDRO")

s = connect("socket.cryptohack.org", 13375)
print(s.recvline())
s.sendline(dumps({
    "option": "vote",
    "vote": hex(int(mod(txt, 256 ^ 16).nth_root(3)))[2:]
}).encode())


print(s.recvline())

```

## Hết

Hmm vậy là mình đã hoàn thành toàn bộ chall RSA, mong phần này sớm có thêm chall vì nó khá hay và kiểu khá nhiều mẹo hay ho.

-3/30/2024-
