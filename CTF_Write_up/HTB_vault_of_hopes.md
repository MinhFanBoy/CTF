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

+ nếu bit = 1 và trả lại `b + e = self.punc_prod(A, self.S) % self.n + self.noise_prod() = self.punc_prod(A, self.S) % self.n + randbelow(2*self.n//3) - self.n//2` tức

$$ - 2 * n / 3 < b + e < n + 2 * n / 3 - n/2 $$

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

---
**_source.py_**

```

from random import randint, shuffle
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from secret import *
import os

assert sha256(KEY).hexdigest().startswith('786f36dd7c9d902f1921629161d9b057')

class BBS:
    def __init__(self, bits, length):
        self.bits = bits
        self.out_length = length

    def reset_params(self):
        self.state = randint(2, 2 ** self.bits - 2)
        self.m = getPrime(self.bits//2) * getPrime(self.bits//2) * randint(1, 2)
    
    def extract_bit(self):
        self.state = pow(self.state, 2, self.m)
        return str(self.state % 2)

    def gen_output(self):
        self.reset_params()
        out = ''
        for _ in range(self.out_length):
            out += self.extract_bit()
        return out

    def encrypt(self, msg):
        out = self.gen_output()
        key = sha256(out.encode()).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return (iv.hex(), cipher.encrypt(pad(msg.encode(), 16)).hex())

encryptor = BBS(512, 256)

enc_messages = []
for msg in MESSAGES:
    enc_messages.append([encryptor.encrypt(msg) for _ in range(10)])

enc_flag = AES.new(KEY, AES.MODE_ECB).encrypt(pad(FLAG, 16))

with open('output.txt', 'w') as f:
    f.write(f'{enc_messages}\n')
    f.write(f'{enc_flag.hex()}\n')
```
----

**Phân tích:**

Đây là bài về AES gồm 2 phần:
+ phần 1: khôi phục lại msg
+ phần 2: từ msg vừa khôi phục tìm lại key và giải mã ciphertext

Các msg được chia ra rồi mã hóa bằng hàm của chương trình:
```py
for msg in MESSAGES:
    enc_messages.append([encryptor.encrypt(msg) for _ in range(10)])
```

với hàm mã hóa
```py

class BBS:
    def __init__(self, bits, length):
        self.bits = bits
        self.out_length = length

    def reset_params(self):
        self.state = randint(2, 2 ** self.bits - 2)
        self.m = getPrime(self.bits//2) * getPrime(self.bits//2) * randint(1, 2)
    
    def extract_bit(self):
        self.state = pow(self.state, 2, self.m)
        return str(self.state % 2)

    def gen_output(self):
        self.reset_params()
        out = ''
        for _ in range(self.out_length):
            out += self.extract_bit()
        return out

    def encrypt(self, msg):
        out = self.gen_output()
        key = sha256(out.encode()).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return (iv.hex(), cipher.encrypt(pad(msg.encode(), 16)).hex())

encryptor = BBS(512, 256)
```

Có:
+ `reset_params` là hàm tạo m và state một cách ngẫu nhiên
+ `extract_bit` trả lại bit của $ ({state} ^ 2) $ % m % 2
+ `gen_output` trả lại một chuỗi bytes là kết của của hàm `extract_bit`
+ `encrypt` là hàm mã hóa AES bình thường với key là kết quả của hàm `gen_output`, một iv random và trả lại iv và ciphertext.

Nhìn kỹ hơn vào hàm `extract_bit`:

```py
    def extract_bit(self):
        self.state = pow(self.state, 2, self.m)
        return str(self.state % 2)
```

Mình thấy rằng nếu state và m cùng chẵn thì ${state} ^ 2$ cũng sẽ chẵn nên dẫn tới ${state} ^ 2 \pmod{m}$  cũng sẽ chẵn nên ${state} ^ 2 \pmod{m} \pmod{2}$  = 0, mà state sau lại được tính bằng `state = pow(self.state, 2, self.m)` nên các state sau cũng sẽ chẵn cùng nhau. Từ đó mình thấy hàm `gen_output` cũng sẽ trả lại các bytes `\x00` và nó cũng được sử dụng làm key để mã hóa AES từ đó mình có thể tìm lại các msg.

```py
from output import *
from random import randint, shuffle
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import os

out = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

key_sha = sha256(out.encode()).digest()

lst = []

for i in enc:
    for j in i:
        try:
            iv = bytes.fromhex(j[0])
            cipher = AES.new(key_sha, AES.MODE_CBC, iv)
            lst.append(cipher.decrypt(bytes.fromhex(j[1])).decode())
            break
        except:
            pass

for i in lst:
    print(i)

```

Với code trên mình thu lại được msg ban đầu như sau:

```
Welcome! If you see this you have successfully decrypted the first message. To get the symmetric key that decrypts the 
flag you need to do the following:

1. Collect all 5 shares from these messages
2. Use them to interpolate the polynomial in a finite field that will be revealed in another message
3. Convert the constant term of the polynomial to bytes and use it to decrypt the flag. Here is your first share!      

Share#1#: (1, 27006418753792019267647881709336369603809025474153761185424552629526746515909)♣♣♣♣♣
Keep up the good work! Offered say visited elderly and. Waited period are played family man formed. He ye body or made 
on pain part meet. You one delay nor begin our folly abode. By disposed replying mr me unpacked no. As moonlight of my 
resolving unwilling. Turned it up should no valley cousin he. Speaking numerous ask did horrible packages set. Ashamed 
herself has distant can studied mrs.

Share#2#: (2, 76590454267924193303526931251420387908730989759486987968207839464816350274449)

Only a few more are left! Of be talent me answer do relied. Mistress in on so laughing throwing endeavor occasion welcomed. Gravity sir brandon calling can. No years do widow house delay stand. Prospect six kindness use steepest new ask. 
High gone kind calm call as ever is. Introduced melancholy estimating motionless on up as do. Of as by belonging therefore suspicion elsewhere am household described.

Share#3#: (3, 67564500698667187837224046797217120599664632018519685208508601443605280795068)♫♫♫♫♫♫♫♫♫♫♫♫♫♫
You are almost there! Not him old music think his found enjoy merry. Listening acuteness dependent at or an. Apartments thoroughly unsatiable terminated sex how themselves. She are ten hours wrong walls stand early. Domestic perceive on an ladyship extended received do. Why jennings our whatever his learning gay perceive. Is against no he without subject. Bed connection unreserved preference partiality not unaffected.

Share#4#: (4, 57120102994643471094254225269948720992016639286627873340589938545214763610538)
Congratulations!!! Not him old music think his found enjoy merry. Listening acuteness dependent at or an. Apartments thoroughly unsatiable terminated how themselves. She are ten hours wrong walls stand early. Domestic perceive on an ladyship extended received do. You need to interpolate the polynomial in the finite field GF(88061271168532822384517279587784001104302157326759940683992330399098283633319).

Share#5#: (5, 87036956450994410488989322365773556006053008613964544744444104769020810012336)
```

Sau khi đọc msg trên mình thấy cần phải tìm key như sau:

+ Tạo một đa thức trên GF(88061271168532822384517279587784001104302157326759940683992330399098283633319) thỏa mãn 5 điểm sau:

        s_1 = (1, 27006418753792019267647881709336369603809025474153761185424552629526746515909)
        s_2 = (2, 76590454267924193303526931251420387908730989759486987968207839464816350274449)
        s_3 = (3, 67564500698667187837224046797217120599664632018519685208508601443605280795068)
        s_4 = (4, 57120102994643471094254225269948720992016639286627873340589938545214763610538)
        s_5 = (5, 87036956450994410488989322365773556006053008613964544744444104769020810012336)

+ Lấy phần hằng số của đa thức đem đi hash sha_256 để tìm lại được key.

Biết đa thức mình cần tìm có dạng $y = a * x ^ 4 + b * x ^ 3 + c * x ^ 2 + d * x + e \pmod(q)$

mình có nhiều hướng như đưa về ma trận, hoặc thay điểm, .. nhưng ở đây mình có dùng hàm viết sẵn của sage để làm.

```py
P = GF(88061271168532822384517279587784001104302157326759940683992330399098283633319)
x1 = (1, 27006418753792019267647881709336369603809025474153761185424552629526746515909)
x2 = (2, 76590454267924193303526931251420387908730989759486987968207839464816350274449)
x3 = (3, 67564500698667187837224046797217120599664632018519685208508601443605280795068)
x4 = (4, 57120102994643471094254225269948720992016639286627873340589938545214763610538)
x5 = (5, 87036956450994410488989322365773556006053008613964544744444104769020810012336)
R = P['x']
a = R.lagrange_polynomial([x1,x2,x3,x4,x5])

print(a.constant_coefficient())
```

Tới đây là mình gần tìm được key rồi, chỉ cần hash và gải mã lại là có flag.

```py
KEY = long_to_bytes(22331541891232741461963319196247128182955676795440837739609455776666597012019)

print(AES.new(KEY, AES.MODE_ECB).decrypt(bytes.fromhex(enc_flag)))
```

### 4. Not that random

----

**_server.py_**

```py
from Crypto.Util.number import *
from Crypto.Random import random, get_random_bytes
from hashlib import sha256
from secret import FLAG

def success(s):
    print(f'\033[92m[+] {s} \033[0m')

def fail(s):
    print(f'\033[91m\033[1m[-] {s} \033[0m')

MENU = '''
Make a choice:

1. Buy flag (-500 coins)
2. Buy hint (-10 coins)
3. Play (+5/-10 coins)
4. Print balance (free)
5. Exit'''

def keyed_hash(key, inp):
    return sha256(key + inp).digest()

def custom_hmac(key, inp):
    return keyed_hash(keyed_hash(key, b"Improving on the security of SHA is easy"), inp) + keyed_hash(key, inp)

def impostor_hmac(key, inp):
    return get_random_bytes(64)

class Casino:
    def __init__(self):
        self.player_money = 100
        self.secret_key = get_random_bytes(16)
    
    def buy_flag(self):
        if self.player_money >= 500:
            self.player_money -= 500
            success(f"Winner winner chicken dinner! Thank you for playing, here's your flag :: {FLAG}")
        else:
            fail("You broke")
    
    def buy_hint(self):
        self.player_money -= 10
        hash_input = bytes.fromhex(input("Enter your input in hex :: "))
        if random.getrandbits(1) == 0:
            print("Your output is :: " + custom_hmac(self.secret_key, hash_input).hex())
        else:
            print("Your output is :: " + impostor_hmac(self.secret_key, hash_input).hex())

    def play(self):
        my_bit = random.getrandbits(1)
        my_hash_input = get_random_bytes(32)

        print("I used input " + my_hash_input.hex())

        if my_bit == 0:
            my_hash_output = custom_hmac(self.secret_key, my_hash_input)
        else:
            my_hash_output = impostor_hmac(self.secret_key, my_hash_input)

        print("I got output " + my_hash_output.hex())

        answer = int(input("Was the output from my hash or random? (Enter 0 or 1 respectively) :: "))

        if answer == my_bit:
            self.player_money += 5
            success("Lucky you!")
        else:
            self.player_money -= 10
            fail("Wrong!")

    def print_balance(self):
        print(f"You have {self.player_money} coins.")



def main():
    print("Welcome to my online casino! Let's play a game!")
    casino = Casino()

    while casino.player_money > 0:
        print(MENU)
        option = int(input('Option: '))

        if option == 1:
            casino.buy_flag()
                
        elif option == 2:
            casino.buy_hint()
                
        elif option == 3:
            casino.play()
                
        elif option == 4:
            casino.print_balance()
            
        elif option == 5:
            print("Bye.")
            break
        
    print("The house always wins, sorry ):")

if __name__ == '__main__':
    main()

```
----

**Phân tich:**


Server cho ta 5 lựa chon ứng với 5 hàm của class Casino như sau:
+ `buy_flag` sẽ gửi cho ta flag khi số coin lớn hơn 500.
+ `buy_hint` cho chúng ta nhập input và ngẫu nhiên trả lại `custom_hmac` hoặc `impostor_hmac`

        def keyed_hash(key, inp):
            return sha256(key + inp).digest()
        
        def custom_hmac(key, inp):
            return keyed_hash(keyed_hash(key, b"Improving on the security of SHA is easy"), inp) + keyed_hash(key, inp)
        
        def impostor_hmac(key, inp):
            return get_random_bytes(64)

+ hàm `keyed_hash` sẽ yêu cầu nhập hai đoạn bytes và trả lại hash của hai đoạn bytes đó
+ `custom_hmac` trả lại `keyed_hash(keyed_hash(key, b"Improving on the security of SHA is easy"), inp) + keyed_hash(key, inp)`
+ `impostor_hmac` trả lại các bytes ngẫu nhiên
  
+ `play` đưa cho ta input và output, bắt ta phải đoán đó là kết quả của hàm `custom_hmac` hay `impostor_hmac`
+ `print_balance` và `Bye` không quan trọng nên mình bỏ qua.

**solution:**

Mình cần phải so sánh kết quả của hàm tả lại để tìm xem nó là kết quá của hàm nào.

với hàm

```py

        def custom_hmac(key, inp):
            return keyed_hash(keyed_hash(key, b"Improving on the security of SHA is easy"), inp) + keyed_hash(key, inp)
```

mình thấy phần `keyed_hash(key, b"Improving on the security of SHA is easy")` này luôn cố định nên nếu chúng ta biết được nó và imput thì ta hoàn đoán có thể đoán đó là hàm custom hay impostor.

Để tìm nó thì mình dùng hàm `get_hint`:

```py
        if random.getrandbits(1) == 0:
            print("Your output is :: " + custom_hmac(self.secret_key, hash_input).hex())
        else:
            print("Your output is :: " + impostor_hmac(self.secret_key, hash_input).hex())
```

tuy nó có thể ngẫu nhiên trả lại hàm custom hoặc impostor. Mình gửi đi b"Improving on the security of SHA is easy" thì dễ dàng có lại keyed_hash(key, b"Improving on the security of SHA is easy") bây giờ chỉ cần so sánh hash mà servert trả về với hash của mình tính nếu nó thỏa mãn thì gửi lại số 0, nêu không thỏa mã thì gửi số 1.

**code:**

```py
from pwn import *
from hashlib import *
from Crypto.Util.number import *  
from tqdm import *

s = connect("83.136.248.97", 43808)

def keyed_hash(key: bytes, inp: bytes) -> bytes:
    return sha256(key + inp).digest()

def get() -> None:

    s.sendlineafter(b"Option: ", b"3")
    s.recvuntil(b"I used input ")
    inp = bytes.fromhex(s.recvline()[:-1].decode())
    s.recvuntil(b"I got output ")
    out = bytes.fromhex((s.recvline()[:-1]).decode())
    print(keyed_hash(hash, inp))
    print(out)
    if out.startswith(keyed_hash(hash, inp)):
        rand = 0
    else:
        rand = 1
    print(rand)
    s.sendlineafter(b":: ", str(rand).encode())

    return s.recvline()

s.recvline()
s.sendlineafter(b"Option: ", b"2")
s.sendlineafter(b"Enter your input in hex :: ", hex(bytes_to_long(b"Improving on the security of SHA is easy"))[2:].encode())
s.recvuntil(b":: ")

hash = bytes.fromhex(s.recvline()[:-1].decode()[-64:])

for i in tqdm(range(90)):
    print(get())

s.sendlineafter(b"Option: ", b"1")

print(s.recv())
```

Phạm Công Minh

-5/23/2024-
