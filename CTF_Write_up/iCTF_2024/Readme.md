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
