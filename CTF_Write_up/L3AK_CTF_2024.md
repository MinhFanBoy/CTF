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
+ ${flag} ^ {65537}  = enc_3 \pmod{n_3}$



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

### 2. related

---

**_chal.py_**

```py
import random
from flag import FLAG
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x101

def pad(flag):
    m = bytes_to_long(flag)
    a = random.randint(2, n)
    b = random.randint(2, n)
    return (a, b), a*m+b

def encrypt(flag):
    padded_variables, padded_message = pad(flag)
    encrypted = pow(padded_message, e, n)
    return padded_variables, encrypted

variables, ct1 = encrypt(FLAG)
a1 = variables[0]
b1 = variables[1]

variables, ct2 = encrypt(FLAG)
a2 = variables[0]
b2 = variables[1]

print(f"{n = }")
print(f"{a1 = }")
print(f"{b1 = }")
print(f"{ct1 = }")
print(f"{a2 = }")
print(f"{b2 = }")
print(f"{ct2 = }")
```

---

**Phân tích:**

Ban đầu, nó sẽ tạo ra các biến public key như sau:

```py
p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x101
```

sau đó flag sẽ được đưa qua hàm `pad`

```py
def pad(flag):
    m = bytes_to_long(flag)
    a = random.randint(2, n)
    b = random.randint(2, n)
    return (a, b), a*m+b
```

hàm này sẽ trả về hai biến a, b hoàn toàn ngẫu nhiên và a * m + b với m là tham số ta nhập vào

sau đó nó sẽ qua hàm encrypt như RSA bình thường

```py
def encrypt(flag):
    padded_variables, padded_message = pad(flag)
    encrypted = pow(padded_message, e, n)
    return padded_variables, encrypted
```

mình sẽ nhận được 2 cái flag đã mã hóa cùng với hai tham số a, b của mỗi lần mã hóa (đương nhiên là có cả public key nữa).

**Solution:**

Từ những dữ kiện đã có thì mình có thể tóm gon nó thành hai phương trình như sau:

+ $(a_1 * {flag} + b_1) ^ e = {enc_1} \pmod{n}$
+ $(a_2 * {flag} + b_2) ^ e = {enc_2} \pmod{n}$

Mình chuyển vế nó để đưa về dạng phương trình như sau:

+ $(a_1 * {flag} + b_1) ^ e - {enc_1} = 0 \pmod{n}$
+ $(a_2 * {flag} + b_2) ^ e - {enc_2} = 0 \pmod{n}$

Khi đó mình có thể ap dụng gcd để tính lại flag như sau:

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/f74b9550-48a6-42f7-a161-a5ee1678fc27)

giả sử flag = x ta thấy

+ $(a_1 * {x} + b_1) ^ e - {enc_1} = 0 \pmod{n}$
+ $(a_2 * {x} + b_2) ^ e - {enc_2} = 0 \pmod{n}$

vì flag đều là nghiệm của phương trình trên nên ta có thể viết lại thành :

+ $(a_ 1 * {x} ^ 5 + b_1 * x ^ 4 ...) * (c_1 * {flag} - d_1)  = 0 \pmod{n}$
+ $(a_2 * {x} ^ 5 + b_2 * x ^ 4 ...) * (c_2 * {flag} - d_2)  = 0 \pmod{n}$

khi đó mình dễ thấy $(a * {flag} - b)$ = gcd($(a_ 1 * {x} ^ 5 + b_1 * x ^ 4 ...) * (c_1 * {flag} - d_1)$, $(a_2 * {x} ^ 5 + b_2 * x ^ 4 ...) * (c_2 * {flag} - d_2) $) = gcd($(a_1 * {flag} + b_1) ^ e - {enc_1}$, $(a_2 * {flag} + b_2) ^ e - {enc_2}$)

Và mình chỉ cần tính lại ${flag} = (-a)/b \pmod{n}$

Từ đó mình đã hoàn thành bài này.

**Code:**

```py

from Crypto.Util.number import *

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a.monic()
e = 0x101
n = 23446116820809956009508921267229329419806339208735431213584717790131416299556366048048977867380629435292555358502917305856047632651197352306945681062223443217527823509039445684919455982744684852068434951030105274549124012946448685060750456093120953320196777137936137902703756422225716380021864017594031233341531336018572970546112899850343992552126107820367629786159724290948728494321350895295087900001068499072242213916345639268473176748281877628559969801359815109260695490545357491404689132480248206287353580339535458835525161032145136894301169515951010316007454927062229765757932923091679510627796469997185047770119
a1 = 8104040836262507446864591234691358718164908580334110843106050982408624642389131164005601569999434432648709609777743793997208912520844943698036947408725027128235833538793471035056805185723079446135588491317378316082567779128276652380455054959975686544145446500257748715018799178783100289455255670805079936852471138049711583797615770901244436979110584710970079641409159097959783566594440737682826559724447739807028855072087914855150495360099989261682566388742966224528680792157619533719489447251411976029565538810357759752921276377948448704648350306514866111068184157760563297810978279434204440014428745729905509605285
b1 = 1728445028759460100268916851157941317747744991464848324630394207912877842639961858831903114707815701742483947978256582554473425946268457939887471248397622887505458768276338958573804608581353987536415380192782284575648580559755923454408763552113403890642303139141765381991794536720006159278517578791058556250982111713910060167032647218698362613084823406687399478088149985930840603408274198692032083156828441656375986195794109996772306557258447129571560905620272546405603257541870547380051900022925294193741417962861863860715434297040138205460211370506997331099668562619882982110566078451957682401843673938997454325985
ct1 = 7133574145118001624468851232768367610776481589816189114081484875167835285211475440236501712634938993477027789627285581268361018888589847771555770716521123959004389671272089766710340921550798461319697963644164596608774387203602804547184454077314801365322929817266934087883757605888082111393091270686060676504784482770435773757625762542094784777964406426404482882414828990658303263295993951921074284755818657012216398826105099627761519486438690405668440835527144374828045319113524249938249744799530870449189528166252037249009094063960558703857141043081099174412277124506544776530125652348821688752923438304710034397792
a2 = 6932198124642373427967232343817468902255209063707505631753623131468591968939116907766874533903771236309508029958603993113318003707536772796355326212684792901937391081839814883783063784050698582961314998290360613480778658142959804536224436521802834308095784814005774038096434723020316915995654759582638114351622288228138452404715021874261743824588698845194567350953613460211780903933501965152586633117799392776012574047439430079820078546000748259648002297803211427390366076552057374120223207399161502626197672749700677144769182115211864885324511059266535644202147069163420794861424973102200053615106664642762054707456
b2 = 17570492860498497589391311850810042101436988882059207563836745301643757694348737390349588510867234608796253222240056487274815481193573640552151307710984790365040907600873879523821340341063776797845384078798440533883164972773525749702026085462782235008812515983104980108840777316735468521572249232663287631112374534186975231033281807029801530398687397396929300293283833448151885674196708775598652356402354479252567714152805778278207736053329489014866155493921442482258381840272615320018058870234668488517354399053820878325928972260161611818894133121294554947400621261460441395783860055835185154356326202402937413717222
ct2 = 8778761624514690203726370366823530128900480928985439769115219364620387269991756967930541323829570453896164780238656562595733025340650482503284244625778872560261904887674968133049252085507078563540106328260114811619983171932648876602484063356832075687231100750407167402096299904835776594509894740386041222719008023556447633524625419665210188090816622517361786836014525679069179481575048514551967532281399777505866483289055530051032001545010914680661193107730444980281645735808124289602346876529763644878375393094200846185413267940739865639764057094273259729425291615810027734657664217752026488492540376475948687563210

PR.<x> = PolynomialRing(Zmod(n))

f_1 = (a1 * x + b1) ^ e - ct1
f_2 = (a2 * x + b2) ^ e - ct2

f = gcd(f_1, f_2)

print(bytes.fromhex(hex(- 1 * f.constant_coefficient())[2:]))

```

### 3. Pailient_tourist 

---

**_chal.sage_**

```py
from sage.all import *
from random import randint
from Crypto.Util.number import *

class Paillier:
    def __init__(self, bits):
        self.bits = bits
        self.pub, self.priv = self.keygen()

    def keygen(self):
        p = random_prime(2**self.bits)
        q = random_prime(2**self.bits)
        Lambda = (p - 1) * (q - 1)
        n = p * q
        Zn = IntegerModRing(n)
        Zn2 = IntegerModRing(n**2)
        g = Zn2(n + 1)
        mu = Zn(Lambda)**-1
        return ((n, g), (Lambda, mu))

    def encrypt(self, m):
        (n, g) = self.pub
        Zn2 = IntegerModRing(n**2)
        r = Zn2(randint(0, n))
        c = g**Zn2(m) * r**n
        return c

    def add(self, cipher_1, cipher_2):
        (n, g) = self.pub
        Zn2 = IntegerModRing(n**2)
        r = Zn2(randint(0, n))
        return cipher_1 * cipher_2 * r**n

    def sub(self, cipher_1, cipher_2):
        (n, g) = self.pub
        Zn2 = IntegerModRing(n**2)
        r = Zn2(randint(0, n))
        inv_cipher_2 = Zn2(cipher_2)**-1
        return cipher_1 * inv_cipher_2 * r**n

    def get_keys(self):
        return self.pub, self.priv

def toStr(msg):
    return long_to_bytes(int(msg))

# Generate key pairs
def main():
    paillier = Paillier(1024)
    pub_key, priv_key = paillier.get_keys()
    message_1 = randint(0, 420)
    cipher_1 = paillier.encrypt(message_1)
    message_2 = bytes_to_long(b"im so smrt, check me out mom")
    cipher_2 = paillier.encrypt(message_2)
    flag_message = bytes_to_long(b"L3AK{FAKE_FLAG_FAKE_FLAG}")
    flag_cipher = paillier.encrypt(flag_message)
    diff_cipher = paillier.sub(cipher_2, cipher_1)
    flag_cipher_modified = paillier.add(flag_cipher, diff_cipher)
    with open("challenge.txt", "w") as f:
        f.write(f"Ciphertext #1 = {hex(int(cipher_1))}\n")
        f.write(f"Ciphertext #2 = {hex(int(cipher_2))}\n")
        f.write(f"Modified Flag Cipher = {hex(int(flag_cipher_modified))}\n")
        f.write(f"Public Key = {hex(int(pub_key[0]))}, {hex(int(pub_key[1]))}\n")
        f.write(f"Private Key = {hex(int(priv_key[0]))}, {hex(int(priv_key[1]))}\n")
    

if __name__ == '__main__':
    main()
```

---

**Phân_tích:**

Mình sẽ phân tích các hàm của bài này trước:

+ Với hàm `key_gen` mình có:
  
  ```py

    def keygen(self):
        p = random_prime(2**self.bits)
        q = random_prime(2**self.bits)
        Lambda = (p - 1) * (q - 1)
        n = p * q
        Zn = IntegerModRing(n)
        Zn2 = IntegerModRing(n**2)
        g = Zn2(n + 1)
        mu = Zn(Lambda)**-1
        return ((n, g), (Lambda, mu))
  ```

  Tạo ra hai số prime p, q từ đó mình có hai trường Z(n), Z($n ^ 2$) rồi trả lại các tham số ((n, g), (lambda, $mu = {lambda} ^ {- 1}$)) và g = n + 1 (Cần nhớ cái này vì nó rất quan trọng)

+ `encrypt`

    ```py
        def encrypt(self, m):
            (n, g) = self.pub
            Zn2 = IntegerModRing(n**2)
            r = Zn2(randint(0, n))
            c = g**Zn2(m) * r**n
            return c
    ```

Hàm này đơn giản chỉ trả lại mình $enc = g ^ {m} * r ^ {n} \pmod{n ^ 2}$ với $r = {random}$

+ Hàm `add`

    ```py
        def add(self, cipher_1, cipher_2):
            (n, g) = self.pub
            Zn2 = IntegerModRing(n**2)
            r = Zn2(randint(0, n))
            return cipher_1 * cipher_2 * r**n
    ```

Nó trả lại ${c_1} * {c_2} * {r} ^ n \pmod{n ^ 2}$

+ Hàm `sub`

    ```py
        def sub(self, cipher_1, cipher_2):
            (n, g) = self.pub
            Zn2 = IntegerModRing(n**2)
            r = Zn2(randint(0, n))
            inv_cipher_2 = Zn2(cipher_2)**-1
            return cipher_1 * inv_cipher_2 * r**n
    
    ```

Trả lại ${c_1} * {c_2} ^ {- 1} * {r} ^ n \pmod{n ^ 2}$

Sau đó chương trình sẽ thực hiện các phép tính sau:

với msg_1 = randint(0, 420), msg_2 = b"im so smrt, check me out mom", msg_3 = flag. Vậy chúng ta có những gì

+ public_key
+ private_key
+ enc(msg_1), enc(msg_2), enc(msg_3)
+ modified = add(flag_cipher, sub(cipher_2, cipher_1))


**Phân_tích:**

có $enc = {g} ^ m * r ^ n \pmod{n ^ 2}$ và Lambda = (q - 1) * (p - 1)

từ đó ${enc} ^ {Lambda} = ({g} ^ m * (r) ^ n) ) ^ {Lambda} =  {g} ^ {m * {Lambda}} * (r) ^ {n * {Lambda}}  \pmod{n ^ 2}$ 

Mà ta có theo định lý Fermat: $r ^ {phi} = 1 \pmod{n}$ mà phi($n ^ 2$) = $n * (p - 1) * (q - 1)$ nên $r ^ {n * {Lambda}} = 1 \pmod{n ^ 2}$

$\to {enc} ^ {Lambda} =  {g} ^ {m * {Lambda}} = {(n + 1)} ^ {m * {Lambda}}$

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/a2ec0240-4fe1-4b53-ab81-971cb637b955)

Theo wiki ta có:

$\to {enc} ^ {Lambda} = m * {Lambda} * n + 1 \pmod{n ^ 2}$

Thực hiện chia hai vế cho n, nhưng nên nhớ ở đây phần mod($n ^ 2$) cũng bị chia cho n nên phần mod chỉ còn lại n.

$\to ({enc} ^ {Lambda}  - 1) / ({Lambda} * n) = m  \pmod{n}$

$\to ({enc} ^ {Lambda}  - 1) / n * wu = m  \pmod{n}$ (vì $wu = {Lambda} ^ {- 1}$)
