Tables_of_contens
================

## ICTF_2024_Crypto

**Mình viết dựa trên nhiều solution của người khác do mình trong giải này không có làm được nhiều(làm tư liệu tham khảo) cũng như tìm hiểu thêm về các bài sau giải**

### 1. Base_64

Bài này mình thấy cx khá dễ nên để luôn code nhé !

----

**_main.py_**:

```py
from Crypto.Util.number import bytes_to_long

q = 64

flag = open("flag.txt", "rb").read()
flag_int = bytes_to_long(flag)

secret_key = []
while flag_int:
    secret_key.append(flag_int % q)
    flag_int //= q

print(f"{secret_key = }")
```

**_output.txt_**:

```py
secret_key = [10, 52, 23, 14, 52, 16, 3, 14, 37, 37, 3, 25, 50, 32, 19, 14, 48, 32, 35, 13, 54, 12, 35, 12, 31, 29, 7, 29, 38, 61, 37, 27, 47, 5, 51, 28, 50, 13, 35, 29, 46, 1, 51, 24, 31, 21, 54, 28, 52, 8, 54, 30, 38, 17, 55, 24, 41, 1]
```

----

solution:

```py
from Crypto.Util.number import long_to_bytes
secret_key = [10, 52, 23, 14, 52, 16, 3, 14, 37, 37, 3, 25, 50, 32, 19, 14, 48, 32, 35, 13, 54, 12, 35, 12, 31, 29, 7, 29, 38, 61, 37, 27, 47, 5, 51, 28, 50, 13, 35, 29, 46, 1, 51, 24, 31, 21, 54, 28, 52, 8, 54, 30, 38, 17, 55, 24, 41, 1]

enc = 0
for i in range(len(secret_key)):
    enc = enc + (64 ** i) * secret_key[i]
print(long_to_bytes(enc))
```

### 2. intergrity

----

**_main.py_**:

```py
from Crypto.Util.number import *
from binascii import crc_hqx

p = getPrime(1024)
q = getPrime(1024)

n = p*q
e = 65537
tot = (p-1)*(q-1)
d = pow(e, -1, tot)

flag = bytes_to_long(open("flag.txt", "rb").read())
ct = pow(flag, e, n)

#signature = pow(flag, d, n) # no, im not gonna do that
signature = pow(flag, crc_hqx(long_to_bytes(d), 42), n)

print(f"{n = }")
print(f"{ct = }")
print(f"{signature = }")

```

**_out.txt_**:

```py
n = 10564138776494961592014999649037456550575382342808603854749436027195501416732462075688995673939606183123561300630136824493064895936898026009104455605012656112227514866064565891419378050994219942479391748895230609700734689313646635542548646360048189895973084184133523557171393285803689091414097848899969143402526024074373298517865298596472709363144493360685098579242747286374667924925824418993057439374115204031395552316508548814416927671149296240291698782267318342722947218349127747750102113632548814928601458613079803549610741586798881477552743114563683288557678332273321812700473448697037721641398720563971130513427
ct = 5685838967285159794461558605064371935808577614537313517284872621759307511347345423871842021807700909863051421914284950799996213898176050217224786145143140975344971261417973880450295037249939267766501584938352751867637557804915469126317036843468486184370942095487311164578774645833237405496719950503828620690989386907444502047313980230616203027489995981547158652987398852111476068995568458186611338656551345081778531948372680570310816660042320141526741353831184185543912246698661338162113076490444675190068440073174561918199812094602565237320537343578057719268260605714741395310334777911253328561527664394607785811735
signature = 1275844821761484983821340844185575393419792337993640612766980471786977428905226540853335720384123385452029977656072418163973282187758615881752669563780394774633730989087558776171213164303749873793794423254467399925071664163215290516803252776553092090878851242467651143197066297392861056333834850421091466941338571527809879833005764896187139966615733057849199417410243212949781433565368562991243818187206912462908282367755241374542822443478131348101833178421826523712810049110209083887706516764828471192354631913614281317137232427617291828563280573927573115346417103439835614082100305586578385614623425362545483289428
```
----

Hàm `crc_hqx` là hàm tương tự như hàm hash nên việc tìm lại được `d` trở nên bất khả thi nên mình hướng tới cách khác. Sau khi tìm hiểu mình thấy kết quả của hàm `crc_hqx` là một số 2 ** 16 bit nên việc tấn công để tìm được kết quả của `crc_hqx(long_to_bytes(d), 42)` chỉ cần vét cạn.
Từ đó mình có:

+ $c_1 = {flag} ^ e$ mod(n)
+ $c_2 = {flag} ^ {guess}$ mod(n)

+ Dễ thấy với a, b, c = xgcd(e, guess) -> e * b + (guess) * c = a = gcd(e, guess) = 1 vì (e là prime, ..)

khi đó ${signature} ^ b * {ct} ^  c = {flag} ^ {e * b + {guess} * c} = flag$

code:

```py

from Crypto.Util.number import *
from tqdm import *

n = 10564138776494961592014999649037456550575382342808603854749436027195501416732462075688995673939606183123561300630136824493064895936898026009104455605012656112227514866064565891419378050994219942479391748895230609700734689313646635542548646360048189895973084184133523557171393285803689091414097848899969143402526024074373298517865298596472709363144493360685098579242747286374667924925824418993057439374115204031395552316508548814416927671149296240291698782267318342722947218349127747750102113632548814928601458613079803549610741586798881477552743114563683288557678332273321812700473448697037721641398720563971130513427
ct = 5685838967285159794461558605064371935808577614537313517284872621759307511347345423871842021807700909863051421914284950799996213898176050217224786145143140975344971261417973880450295037249939267766501584938352751867637557804915469126317036843468486184370942095487311164578774645833237405496719950503828620690989386907444502047313980230616203027489995981547158652987398852111476068995568458186611338656551345081778531948372680570310816660042320141526741353831184185543912246698661338162113076490444675190068440073174561918199812094602565237320537343578057719268260605714741395310334777911253328561527664394607785811735
signature = 1275844821761484983821340844185575393419792337993640612766980471786977428905226540853335720384123385452029977656072418163973282187758615881752669563780394774633730989087558776171213164303749873793794423254467399925071664163215290516803252776553092090878851242467651143197066297392861056333834850421091466941338571527809879833005764896187139966615733057849199417410243212949781433565368562991243818187206912462908282367755241374542822443478131348101833178421826523712810049110209083887706516764828471192354631913614281317137232427617291828563280573927573115346417103439835614082100305586578385614623425362545483289428

for i in tqdm(range( 2 ** 16)):
    try:
        a, b, c = xgcd(i, 65537)
        # print(b * i + c * 65537)
        print(long_to_bytes(int(pow(signature, b, n) * pow(ct, c, n))).decode())
    except:
        pass
```

### 3. tango

---

**_sever.py_**:

```py
from Crypto.Cipher import Salsa20
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
from secrets import token_bytes, token_hex
from zlib import crc32

# from secret import FLAG

KEY = token_bytes(32)

def encrypt_command(command):
    if len(command) != 3:
        print('Nuh uh.')
        return
    cipher = Salsa20.new(key=KEY)
    nonce = cipher.nonce
    data = json.dumps({'user': 'user', 'command': command, 'nonce': token_hex(8)}).encode('ascii')
    checksum = long_to_bytes(crc32(data))
    ciphertext = cipher.encrypt(data)
    print('Your encrypted packet is:', (nonce + checksum + ciphertext).hex())


def run_command(packet):
    packet = bytes.fromhex(packet)
    nonce = packet[:8]
    checksum = bytes_to_long(packet[8:12])
    ciphertext = packet[12:]

    try:
        cipher = Salsa20.new(key=KEY, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        if crc32(plaintext) != checksum:
            print('Invalid checksum. Aborting!')
            return

        data = json.loads(plaintext.decode('ascii'))
        user = data.get('user', 'anon')
        command = data.get('command', 'nop')

        if command == 'nop':
            print('...')
        elif command == 'sts':
            if user not in ['user', 'root']:
                print('o_O')
                return
            print('The server is up and running.')
        elif command == 'flag':
            if user != 'root':
                print('You wish :p')
            else:
                print("ok, here's the flag:")
        else:
            print('Unknown command.')
    except (json.JSONDecodeError, UnicodeDecodeError):
        print('Invalid data. Aborting!')


def menu():
    print('[E]ncrypt a command')
    print('[R]un a command')
    print('[Q]uit')


def main():
    print('Welcome to the Tango server! What would you like to do?')
    while True:
        menu()
        option = input('> ').upper()
        if option == 'E':
            command = input('Your command: ')
            encrypt_command(command)
        elif option == 'R':
            packet = input('Your encrypted packet (hex): ')
            run_command(packet)
        elif option == 'Q':
            exit(0)
        else:
            print('Unknown option:', option)


if __name__ == '__main__':
    main()

```
---

Đề bài khá dài nhưng nhìn chung mình có thể thu gon nó lại như sau:

+ cho plaintext = "{'user': 'user', 'command': command, 'nonce': token_hex(8)}" được mã hóa bởi Salsa_20 mình cần đưa nó về sao cho `user = root` và `command = flag` và mình cũng không có key, hay bất kỳ thông tin nào được leak.

Tìm hiểu qua về salsa_20 mình thấy nó mã hóa như sau:

![image](https://github.com/user-attachments/assets/ec29ef6a-507c-444b-a1b0-73de4bc7a874)

[Nguồn](https://www.semanticscholar.org/paper/Low-cost-hardware-implementations-of-Salsa-20-in-Jaros%C5%82aw/cf3800b8e0ea55d34167db06502a28732bd5297d)

Từ đó mình thấy Ciphertext = Plaintext xor ENC() mà key luôn được giữ cố định trong cả trương trình nên ENC() cũng sẽ không thay đổi.

vì tính chất của xor nên:
+ ENC() = Ciphertext xor Plaintext
+ New_Ciphertext = New_Plaintext xor ENC() -> New_Ciphertext = New_Plaintext xor Ciphertext xor Plaintext

Do mình đã biết cả 3 cái kia nên mình có thể tính lại được New_Ciphertext và hoàn thành bài này.

code:

```py
from Crypto.Cipher import Salsa20
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
from secrets import token_bytes, token_hex
from zlib import crc32
from pwn import *

s = connect("tango.chal.imaginaryctf.org", 1337)
# s = process(["python3", "server.py"])
print(s.recvuntil(b"> "))
s.sendline(b"E")
s.sendline(b"sts")
s.recvuntil(b"Your encrypted packet is: ")
packet = s.recvline().strip().decode()
packet = bytes.fromhex(packet)
nonce = packet[:8]
checksum = bytes_to_long(packet[8:12])
ciphertext = packet[12:]

data = b'{"user":"root","command":"flag","nonce":""}'
checksum = long_to_bytes(crc32(data))
ciphertext = xor(ciphertext[:len(data)], data, b'{"user": "user", "command": "sts", "nonce": "f84c966c8519fd0f"}'[:len(data)])
packet = (nonce + checksum + ciphertext).hex()
print(s.recvuntil(b"> "))
s.sendline(b"R")
# print(s.recvline())
s.sendline(packet)
print(s.recvline())
```

### 4. solitude

---

**_main.py_**:

```py
#!/usr/bin/env python3

import random

def xor(a: bytes, b: bytes):
  out = []
  for m,n in zip(a,b):
    out.append(m^n)
  return bytes(out)

class RNG():
  def __init__(self, size, state=None):
    self.size = size
    self.state = list(range(self.size+2))
    random.shuffle(self.state)
  def next(self):
    idx = self.state.index(self.size)
    self.state.pop(idx)
    self.state.insert((idx+1) % (len(self.state)+1), self.size)
    if self.state[0] == self.size:
      self.state.pop(0)
      self.state.insert(1, self.size)
    idx = self.state.index(self.size+1)
    self.state.pop(idx)
    self.state.insert((idx+1) % (len(self.state)+1), self.size+1)
    if self.state[0] == self.size+1:
      self.state.pop(0)
      self.state.insert(1, self.size+1)
    if self.state[1] == self.size+1:
      self.state.pop(1)
      self.state.insert(2, self.size+1)
    c1 = self.state.index(self.size)
    c2 = self.state.index(self.size+1)
    self.state = self.state[max(c1,c2)+1:] + [self.size if c1<c2 else self.size+1] + self.state[min(c1,c2)+1:max(c1,c2)] + [self.size if c1>c2 else self.size+1] + self.state[:min(c1,c2)]
    count = self.state[-1]
    if count in [self.size,self.size+1]:
      count = self.size
    self.state = self.state[count:-1] + self.state[:count] + self.state[-1:]
    idx = self.state[0]
    if idx in [self.size,self.size+1]:
      idx = self.size
    out = self.state[idx]
    if out in [self.size,self.size+1]:
      out = self.next()
    return out

if __name__ == "__main__":
  flag = open("flag.txt", "rb").read()
  while True:
    i = int(input("got flag? "))
    for _ in range(i):
      rng = RNG(128)
      stream = bytes([rng.next() for _ in range(len(flag))])
      print(xor(flag, stream).hex())
```
---

Bài này xây dựng một lớp `RNG` để tạo ra các  bytes ngẫu nhiên rồi lấy đầu ra của nó để xor với flag.

Ban đầu mình thấy 
```py
self.state = self.state[max(c1,c2)+1:] + [self.size if c1<c2 else self.size+1] + self.state[min(c1,c2)+1:max(c1,c2)] + [self.size if c1>c2 else self.size+1] + self.state[:min(c1,c2)]
```
có thể giúp mình dịch ngược lại được state ban đầu dựa vào đầu ra của nó nhưng thật sụ nó khá khó và cũng không biết code thế nào.

sao một hồi nghĩ mình nhân thấy :

```py
#!/usr/bin/env python3

import random

def xor(a: bytes, b: bytes):
  out = []
  for m,n in zip(a,b):
    out.append(m^n)
  return bytes(out)

class RNG():
  
  def __init__(self, size, state=None):
    self.size = size
    self.state = list(range(self.size+2))
    random.shuffle(self.state)
    
  def next(self):
    
    idx = self.state.index(self.size)
    self.state.pop(idx)
    self.state.insert((idx+1) % (len(self.state)+1), self.size)
    
    if self.state[0] == self.size:
      self.state.pop(0)
      self.state.insert(1, self.size)
      
    idx = self.state.index(self.size+1)
    self.state.pop(idx)
    self.state.insert((idx+1) % (len(self.state)+1), self.size+1)
    
    if self.state[0] == self.size+1:
      self.state.pop(0)
      self.state.insert(1, self.size+1)
      
    if self.state[1] == self.size+1:
      self.state.pop(1)
      self.state.insert(2, self.size+1)
      
    c1 = self.state.index(self.size)
    c2 = self.state.index(self.size+1)
    self.state = self.state[max(c1,c2)+1:] + [self.size if c1<c2 else self.size+1] + self.state[min(c1,c2)+1:max(c1,c2)] + [self.size if c1>c2 else self.size+1] + self.state[:min(c1,c2)]
    count = self.state[-1]
    
    if count in [self.size,self.size+1]:
      count = self.size
      
    self.state = self.state[count:-1] + self.state[:count] + self.state[-1:]
    idx = self.state[0]
    
    if idx in [self.size,self.size+1]:
      idx = self.size
    out = self.state[idx]
    # print(self.state)
    if out in [self.size,self.size+1]:
      out = self.next()
    return out

if __name__ == "__main__":
  flag = b"bu bu lmao"
  rng = RNG(128)
  tmp = []
  for k in range(1):
    stream = [rng.next() for _ in range(33)]
    print(stream)

    sc = []
    for i in range(128):
      sc.append(stream.count(i))
    tmp.append(sc.index(max(sc)))
  print(tmp)
```

khi chạy code như này để kiểm tra đầu ra của `RNG` mình thấy nó bị lệch tỷ lệ, tức tỷ lệ cho ra bytes `\x00` thường lớn hơn các bytes khác nên tận đụng điều đó mình nhận thật nhiều lần rổi xem ký tự nào xuất hiện nhiều nhất thì đó chính là ký tự của flag chuẩn.

code :

```py

from pwn import *
from Crypto.Util.number import *
from string import *
from tqdm import *
s = connect("solitude.chal.imaginaryctf.org", 1337)

s.recvline()
s.recvuntil(b"got flag? ")

tmp = []
s.sendline(b"100000")
for i in tqdm(range(100000)):
    # print(s.recvline().strip().decode())
    tmp.append(bytes.fromhex(s.recvline().strip().decode()))
    
for i_ in range(33):
    k = [tmp[i][i_]for i in range(100000)]
    count_ = 0
    max_ = 0
    for i in (ascii_letters + digits + "{}_").encode():
        l = k.count(i)
        if l > count_:
            max_ = i
            count_ = l
            
    print(chr(max_), end="")
```

### 5. lf3r

to be continued ...

### 6. coast

---

**_chall.sage_**:

```py
from Crypto.Cipher import AES
from hashlib import sha256

proof.all(False)
# fmt: off
ls = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 929]
# fmt: on
p = 4 * product(ls) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])
G = E0.gen(0)
base = (E0, G)


def keygen():
    return [randint(-1, 1) for _ in range(len(ls))]


def exchange(pub, priv):
    E, G = pub
    es = priv[:]
    while any(es):
        s = +1 if randint(0, 1) else -1
        E.set_order(p + 1)
        P = E.random_point()
        k = prod(l for l, e in zip(ls, es) if sign(e) == s)
        P *= (p + 1) // k
        for i, (l, e) in enumerate(zip(ls, es)):
            if sign(e) != s:
                continue
            Q = k // l * P
            if not Q:
                continue
            Q.set_order(l)
            phi = E.isogeny(Q)
            E, P = phi.codomain(), phi(P)
            G = phi(G)
            es[i] -= s
            k //= l
    return E, G


def serialize_pub(pub):
    E, G = pub
    return (E.a4(), E.a6(), G[0], G[1])


with open("flag.txt", "rb") as f:
    flag = f.read().strip()

priv_alice = keygen()
priv_bob = keygen()
pub_alice = exchange(base, priv_alice)
pub_bob = exchange(base, priv_bob)
shared_1 = exchange(pub_alice, priv_bob)
shared_2 = exchange(pub_bob, priv_alice)
assert shared_1 == shared_2

shared_secret = int(shared_1[0].j_invariant() + shared_1[1][0])
key = sha256(str(shared_secret).encode()).digest()
cipher = AES.new(key, AES.MODE_CTR)
ct = cipher.encrypt(flag)
iv = cipher.nonce

base_ser = serialize_pub(base)
pub_alice_ser = serialize_pub(pub_alice)
pub_bob_ser = serialize_pub(pub_bob)

print(f"{base_ser = }")
print(f"{pub_alice_ser = }")
print(f"{pub_bob_ser = }")
print(f"{ct = }")
print(f"{iv = }")

```

**_out.txt_**:

```py
base_ser = (1, 0, 6395576350626777292729821677181541606370191430555605995902296654660733787961884662675205008112728910627829097716240328518277343733654560980779031197383306195903192278996242667385893559502924064335660043910231897229406366701069814748813352528977494567341233293392314984276702732050363273792561347300313, 4989628161531004318153788074304291273577473031059606908412965124036974844963743869216684686020120111949770513589687750670438648526142795689802013040914101895565898055896213731473214310303864435287131739468789570598441615792162769805326802317670196010077382560220110366549259348962142078308153647899274)
pub_alice_ser = (16796745232047376431076025485853428113133878598097917003461887969217006498108008731966744769172838839455129087919415367459511356804735314320761042839383730282543236466692745670914654548112400401873112245614944913297758267192129423214055383555189748155309668519243823656843679941140887547541583677456851, 8963816826825107706757885015960152371166552220981896678339960705520861493163941960230523020894830135812851365288978634124277530779100695340287569755423459240568704426045331208533913128865584575359563263393253534547084448818884991750356771030230632199257310184446749944357247275509600739836829962695982, 5985363780131483127972578951676841809331634397976984954623788863861777364455401615121494127550821174942018761442458411590922907440513151315213076773138479058971335280960602464177689878904986723530962048747658113657305981717196234378352404797804042544442260172818264948952275310656449986193544911288998, 11649597127875537444034607923163754235537320890125543416303955671947999961428652169037025819875497760380019726767893160005005207635230495183159964997017269895171761165208635703481382384409333096255950930548560628238229917503014555866644994772105200770892341004064761100707021002853325553967825145390381)
pub_bob_ser = (11074315528506118650419974941868902144061087346415910875754699136651403897503986559271837685210876546003254210356095728661380015394250217544836232370667249236726866756134031525443480212922804350247920434230860777321021642812917870058468202706130234985660019235758626667794297106070003964360950607030598, 14788615576129160240974902210621158431820003187709942310686740894110660926275619991889339611525021308542253932884035960214935758630370400596713566372704518819883473808782054060292387578412174017604910767645236213465324157607253511970477802974564062325283523478550237024031582360283010701611159519365278, 14321992806289178321304756176419224025450932661291292547666237239861901427262601709081849960088644959294041693893090273529716185385414362311881174527793744440204632764863112487952716682577231240702585919349036909411205777137409147119242850872654694352308452421920098660171268727320418419754354531076628, 7538734401643277631776877448699813925331537292810845825274725479798688685992383653831671943669387620894416031681699814135234397288844079804264499920949132059399186790837118164550554056080958276489614279355615876249173470199144967698224721556194470026970595690830845832259388888940448493603599827181272)
ct = b'\x8a\x1cs\xa1\xb3\xa77\x81_:\x81\xf8\x83\xc3a\x17\xe1\xd9\xcb\x0c]\x9b\xebP\x06c\x85\x9de1\xeed\x91\x0f\x87_\xf9\x9bD\x7f\xf1\xbdD\x88P\x9eO\x04'
iv = b'\x94j;L,\xf3\xde\xc5'

```

---

[isogeny](https://eprint.iacr.org/2019/1321.pdf)
[CSIDH](https://eprint.iacr.org/2018/383.pdf)

Nói sơ qua về đẳng cấu thì:
+ Mỗi ECC đều có một j_invariant riêng được tính bằng ![image](https://github.com/user-attachments/assets/00199046-b47b-4347-940b-31f651e32bed)

+ Hai ECC được gọi là isogeny (đẳng cấu) khi nó có chung j_invariant (j bất biến)
+ Tóm lại isogeny là một ánh xạ chuyển từ đường cong này sang đường cong khác.
+ Khi cấp của ECC là prime l thì isogeny sẽ tạo thành một nhóm hoán vị cấp l + 1
+ một isogeny thỏa mãn tính chất của nhóm thông thường.

code:
```py
from Crypto.Cipher import AES
from hashlib import sha256
from tqdm import *

proof.all(False)

base_ser = (1, 0, 6395576350626777292729821677181541606370191430555605995902296654660733787961884662675205008112728910627829097716240328518277343733654560980779031197383306195903192278996242667385893559502924064335660043910231897229406366701069814748813352528977494567341233293392314984276702732050363273792561347300313, 4989628161531004318153788074304291273577473031059606908412965124036974844963743869216684686020120111949770513589687750670438648526142795689802013040914101895565898055896213731473214310303864435287131739468789570598441615792162769805326802317670196010077382560220110366549259348962142078308153647899274)
pub_alice_ser = (16796745232047376431076025485853428113133878598097917003461887969217006498108008731966744769172838839455129087919415367459511356804735314320761042839383730282543236466692745670914654548112400401873112245614944913297758267192129423214055383555189748155309668519243823656843679941140887547541583677456851, 8963816826825107706757885015960152371166552220981896678339960705520861493163941960230523020894830135812851365288978634124277530779100695340287569755423459240568704426045331208533913128865584575359563263393253534547084448818884991750356771030230632199257310184446749944357247275509600739836829962695982, 5985363780131483127972578951676841809331634397976984954623788863861777364455401615121494127550821174942018761442458411590922907440513151315213076773138479058971335280960602464177689878904986723530962048747658113657305981717196234378352404797804042544442260172818264948952275310656449986193544911288998, 11649597127875537444034607923163754235537320890125543416303955671947999961428652169037025819875497760380019726767893160005005207635230495183159964997017269895171761165208635703481382384409333096255950930548560628238229917503014555866644994772105200770892341004064761100707021002853325553967825145390381)
pub_bob_ser = (11074315528506118650419974941868902144061087346415910875754699136651403897503986559271837685210876546003254210356095728661380015394250217544836232370667249236726866756134031525443480212922804350247920434230860777321021642812917870058468202706130234985660019235758626667794297106070003964360950607030598, 14788615576129160240974902210621158431820003187709942310686740894110660926275619991889339611525021308542253932884035960214935758630370400596713566372704518819883473808782054060292387578412174017604910767645236213465324157607253511970477802974564062325283523478550237024031582360283010701611159519365278, 14321992806289178321304756176419224025450932661291292547666237239861901427262601709081849960088644959294041693893090273529716185385414362311881174527793744440204632764863112487952716682577231240702585919349036909411205777137409147119242850872654694352308452421920098660171268727320418419754354531076628, 7538734401643277631776877448699813925331537292810845825274725479798688685992383653831671943669387620894416031681699814135234397288844079804264499920949132059399186790837118164550554056080958276489614279355615876249173470199144967698224721556194470026970595690830845832259388888940448493603599827181272)
ct = b'\x8a\x1cs\xa1\xb3\xa77\x81_:\x81\xf8\x83\xc3a\x17\xe1\xd9\xcb\x0c]\x9b\xebP\x06c\x85\x9de1\xeed\x91\x0f\x87_\xf9\x9bD\x7f\xf1\xbdD\x88P\x9eO\x04'
iv = b'\x94j;L,\xf3\xde\xc5'

ls = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 929]

p = 4 * product(ls) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])
G = E0.gen(0)
base = (E0, G)


def keygen():
    return [randint(-1, 1) for _ in range(len(ls))]


def exchange(pub, priv):
    E, G = pub
    es = priv[:]
    while any(es):
        s = +1 if randint(0, 1) else -1
        E.set_order(p + 1)
        P = E.random_point()
        k = prod(l for l, e in zip(ls, es) if sign(e) == s)
        P *= (p + 1) // k
        for i, (l, e) in enumerate(zip(ls, es)):
            if sign(e) != s:
                continue
            Q = k // l * P
            if not Q:
                continue
            Q.set_order(l)
            phi = E.isogeny(Q)
            E, P = phi.codomain(), phi(P)
            G = phi(G)
            es[i] -= s
            k //= l
    return E, G


def serialize_pub(pub):
    E, G = pub
    return (E.a4(), E.a6(), G[0], G[1])

def get_pub(pub):

    a, b, x, y = pub
    
    E = EllipticCurve(F, [a, b])
    E.set_order(p + 1)
    A = E(x, y)
    
    return E, A



E, G = get_pub(base_ser)
EA, GA = get_pub(pub_alice_ser)
EB, GB = get_pub(pub_bob_ser)
k = prod(ls)
key_a = []

E.set_order(p + 1)

GA *= (p + 1) // k
for i in tqdm(range(len(ls))):

    Q = k // ls[i] * GA

    Q.set_order(ls[i])
    phi = str(EA.isogeny(Q))
    # print(type(phi))
    if "Isogeny of degree 1 " in phi:
        key_a.append(1)
    else:
        key_a.append(0)

shared_2 = exchange((EB,GB), key_a)
    
shared_secret = int(shared_2[0].j_invariant() + shared_2[1][0])
key = sha256(str(shared_secret).encode()).digest()
cipher = AES.new(key, AES.MODE_CTR, nonce = iv)
print(cipher.decrypt(ct))
```