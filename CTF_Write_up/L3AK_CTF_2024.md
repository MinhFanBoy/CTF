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

Từ đó ta có thể code lại được hàm decrypt như sau:

```py
def decrypt(c, priv):
	
	((n, g), (Lambda, mu)) = priv

	c = int(pow(c, Lambda, n ^ 2) - 1) // int(n) * mu % n
	
	return c
```

Tuy nhiên ta vẫn chưa có được flag luôn bởi vì nó còn đang bị mã hóa cùng với những msg khác. Tuy nhiên với nó ta có thể tìm lại được msg_1 = b"0x17"

với modified = add(flag_cipher, sub(cipher_2, cipher_1))

thì ta có như sau:

$${modified} = (g ^ {flag} * {r_1} ^ n) * (g ^ {msg_2} * {r_2} ^ n) * ((g ^ {msg_1} * {r_2} ^ n) ^ {- 1})$$

$${modified} = (g ^ {flag + msg_2 - msg_1} * {(r_1 * r_2 // r_3)} ^ n)$$

Sử dụng hàm decrypt trên thì ta có lại được flag + msg_2 - msg_1, việc còn lại chỉ là trừ lại là xong vì msg_1, 2 đều đã biết

**Code:**

```py

from Crypto.Util.number import *

def decrypt(c, priv):
	
	((n, g), (Lambda, mu)) = priv

	c = int(pow(c, Lambda, n ^ 2) - 1) // int(n) * mu % n
	
	return c

enc_1 = 0x14060da59e64dc74087b911f612d2c45d8253cb3d7cb322b3aea545b05460880b7c5cd99cdaad15d2bf7b92a5315c9cf6e1c962ebb1100e1b9d0b5f768419069cb4e53281c15d8a432f90ad33c6a3680c7a56df8680bf22765b4b5977bc30cdb49ea1dab83694268bf6869dcd587a8be2475330c339d441e8ce254559c3fe5e2b0296dd0239924e318d86b4c9f2babd2b49bf103fb6cc340e0bffe0dac3fda06aeb1e763f9d6713d62aee4aa9b7806b9dd1f311a528cd9531d997dfe31190f457af2576a79e4f873da57a28da763e07037dd6c7d14ef978bdcb857c7559ebe774c8db2ca34fc5841df1362ae768db89690216594c48ef23bd131618c3978a3bb36d420907947d862490376e20a9af43583960641b37a5733ee4082f8eb750d30eb8177e8af1d2589785b81d7e74c9ad386ef8280bc6c0d275bb95bb0cffd8b3e73db2e438880ff2f7bdd2bdfc0c8f3ee5265196d11eb9e4f5db8d643d5dc2d7c5372bad82d62cd2966ce033c5c609db288ef8484a664f4e33d19ce218ced0e7f46256c41d827813f4cb65425240762cc6e1c87421ff851c50f0c011e39655640bf3b8db0f43cb5ed93fb1967209d446d996c29abd76fa952fe31050b85d0e350dddc924421c3606d686e72d5764e0a596c95607ecb92a7cc7fe8c8b031e2877774f7df1e842107a4048306449ca7d66eb0cbfcd13b6b6cd3e2ae719b8e20530
enc_2 = 0x50258985886970e93e6b0105d26e42efe033a8216f721eaf981f89e9287b04ddfe5f16d3f6fcef6e814376c266e6738b29e47eb70b97fa9ff03e0e29e17d32d131550b94df94b7484f73592ecd15848594e9fc93e3401848b437bd6a8c67159c5410a32eebeab7285365ea69bfeeaaef975af1dd55c250bc30c709cdc631aa678f7e2795c6c5d66187974de4c6bfb30da14a9f9a91fcac9eccb463196d621ecdbeda28d682401c960a2dca58730766a6cecb83630ca92523b5bdd7c97019adc1754d0598d082cf51337e434bd2683d70ca074c276dc0e386a3a9a9ef189eff84a2acbdd7c1891c113589244d41d541dbc7a88639ab05b3c57cdd8fdfdbc7d3a9619bb8b0db85ce3e66640d2e1821da55ebdfb09e73230a08ad49d72707d4639763c8196568eb5654466743dd66c6cf37fafc97004aa0c063f54b145fb8d33dea6eb371af6e66d3e6fb3fa082712b5e4ad70580808fd650cc056aa17a88cc4ad0387701237f81a7039071aac653314a7dfe6fccd2b1e87cdf43832425a97ff9c5383133b6e984d9fb2132a80ee9b05cc7a2a493f9bc2197ba940826cdedd667a515d1554539eabc1ebdc9dd2075b80f98fa5e125a78891e64eb57f5e5eba97200d5c76f5d49646eda8671f5d289c1f8ca7c5033466b636052f10fbf0026c3c15f19b805271f9322a1c674cc33f69b725feb8a9087c05cc490c63fb467f499d9f
enc = 0x410f09e83a921ff2e06f9af688d56962be6b6db5472d84c802c89505bc80dcb06f09fba8cea712f3bd0af654b1e9c7010a20fe4bee9537c3e44771b90547103f9a313df10de3df68862c98ce7bfff47dc0547b65867b0990fd9ac496bf8e5df6c4fc8ad2ad074fb5083532dbb1f2373b9183770e2fda35498fa1753bb8ec4b1fcf80f100ae20eb8e865ef80e46435f75ec998af6cebb64717d76af38f926470207b8753bd94c0e55d7eaf7a5c352d718feead815aa886e585865c812f840da04fa24f411fc5917efcfc7549a41a22aed031842309709d93eb4818c62a00614f0ac13ac909454cb56780658d6188f813ba77ae52b76b2979423d9e62118a17114b8572a3219fda1e9399d91249fbb32b4e06615ce91de513f14231f42fe6b1e27027a22841554399b5c699a68dd308f0d11ed00580d703e9ea61710378b06bf3e55a4c6405e523184a3f4f9838c06ee650c7002b69106c8d7569c7f0628093fe61acbd2ce52654f6ebed132789daba9b26b989e3c6283326dec6c63df9ecfb60620cac002e680691d3cb8e4b4139596973a333eb5942f8512919e6b338631675c2c9ab58115aeaee009870a2a3d121c16574476211cdac81b78618f101315c694005ab7478546538e43559c3d29fb9508a1ca5a6e7afc046d0b450165f34ed611156ab9485adffd118013f8477ed8b7cf95f9008d0f140226644c99920af5633
n, g = 0x250fb952a1b9ed84701fa2fe7b90615e4144635d26a566231e2eeefae591c74fdf8a775425cf26ee84b48460417ff1859f4279c703258b325e7196656293c9225db58a9b6054fa83a2e44fc00eb058dd3e1660fbdc79cfd427aa90b0e0efdc40e02753c715ea9e7de1f282554d99c22ba883ca433577f8eac31dcfa55117c933cb69c969d91065a5276eb07e81caaf4fb332cc0f40cf5c049b8e8c78288f7b7a7d71fc5e1dba03eab6359bca909157e8a422c03ec852ae8b6fd8eaf7a37b2e3b680448f42724a3431aa73df3debdc052791ee2d0d57499fa2f1a21cb10bfdd14c148545d59fb7c90b679d44d4ad298ea6e15f4782faf9c53b8c3cda7536f11a5, 0x250fb952a1b9ed84701fa2fe7b90615e4144635d26a566231e2eeefae591c74fdf8a775425cf26ee84b48460417ff1859f4279c703258b325e7196656293c9225db58a9b6054fa83a2e44fc00eb058dd3e1660fbdc79cfd427aa90b0e0efdc40e02753c715ea9e7de1f282554d99c22ba883ca433577f8eac31dcfa55117c933cb69c969d91065a5276eb07e81caaf4fb332cc0f40cf5c049b8e8c78288f7b7a7d71fc5e1dba03eab6359bca909157e8a422c03ec852ae8b6fd8eaf7a37b2e3b680448f42724a3431aa73df3debdc052791ee2d0d57499fa2f1a21cb10bfdd14c148545d59fb7c90b679d44d4ad298ea6e15f4782faf9c53b8c3cda7536f11a6
Lambda, mu = 0x250fb952a1b9ed84701fa2fe7b90615e4144635d26a566231e2eeefae591c74fdf8a775425cf26ee84b48460417ff1859f4279c703258b325e7196656293c9225db58a9b6054fa83a2e44fc00eb058dd3e1660fbdc79cfd427aa90b0e0efdc40e02753c715ea9e7de1f282554d99c22ba883ca433577f8eac31dcfa55117c933057d339c308438050366c6b40808a18b4448dfe495c06abe52abdaaeb86381c86a14ad5d91ff1b25aaf1e82d0e429c8622cd435389169a066357ef488c1725ec0812d3a8edd7bc93d5ac7344c074169dbfd52949913cb9779ce1f7aab96b9a8a554fb17493075a862ab37d30ea4fe91e5ee6f9b95e280b297e91357454800c60, 0x21c0ff97d130be489dd28344be8a9022b1ecbca51a8555c52e3512f65786623289f7effbda90d9e52e3066af88464b5157984983fdbd4a0a60eea984bb427230d6f4e0de54954ccc8efc58127b58fb02fed0ea47f4bd28072be2e02fa58abf65d15a644a55f847feca9e29596aa9fb6137d0bfa68c1a69e1f425f20063c8bf256b7aa3920b149169ca4cabbe2c3668d8edbca2d0f7e7d0d131397a0b102339f6824153f7b6bc7837f255dd947ef53607e0ef91f08665e9125fc374689c3d515985d28313e1b9d4c2554e8780bb485f3e7c5999a30b94d2b5d0762b5adf7a031782a0488249ca109e9590aa9e611ed2dbc4ea9758d397d30ce11b0f8c2a683bc6

msg_1 = randint(0, 420)
msg_2 = bytes_to_long(b"im so smrt, check me out mom")


priv = ((n, g), (Lambda, mu))

print(long_to_bytes(int(decrypt(enc_1, priv))))
print(long_to_bytes(int(decrypt(enc_2, priv))))
print(long_to_bytes(int(decrypt(enc, priv) - msg_2 + 0x17)))


```
