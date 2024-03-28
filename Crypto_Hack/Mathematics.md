Tables_of_contens
=================

### Crypto

Dạo này đang khá rảnh nên mình rành thời gian ra học crypto cũng như học toán a3 thể luôn sắp trượt mọe rồi..
> Có mấy bài khá dễ mình lỡ làm trước rồi giờ lười viết lại nên không có...

### 1. Gram Schmidt

---
**_TASK:_**

```txt
To test your code, let's grab the flag. Given the following basis vectors:

    v1 = (4,1,3,-1), v2 = (2,1,-3,4), v3 = (1,0,-2,7), v4 = (6, 2, 9, -5),

use the Gram-Schmidt algorithm to calculate an orthogonal basis. The flag is the float value of the second component of u4 to 5 significant figures.
```

```py
u1 = v1
Loop i = 2,3...,n
   Compute μij = vi ∙ uj / ||uj||2, 1 ≤ j < i.
   Set ui = vi - μij * uj (Sum over j for 1 ≤ j < i)
End Loop
```
---

Bài này yêu cầu mình sử dụng thuật toán Gram-Schmidt để tính một ma trận khác.

Nói sơ qua về thuật toán trên (mình thấy nói khá khó hiểu):
+ Đây là một thuật toán để trực chuẩn hóa các vector cho trước, trong một không gian tích trong(tích trong là kiểu nhân vector mà mình đã học lớp 10 inner product) với đầu vào là một tập hợp hữu hạn các vector độc lập tuyến tính với nhau. Và tạo ra một tập hợp các vector khác đôi một vuông goc với  với nhau.
+ Công thức tổng quát ở [đây](https://en.wikipedia.org/wiki/Gram%E2%80%93Schmidt_process)

```py

v1 = (4,1,3,-1)
v2 = (2,1,-3,4)
v3 = (1,0,-2,7)
v4 = (6, 2, 9, -5)

v= [v1, v2, v3, v4]
u = [v1]

def _length(v_1 : list, v_2) -> int:
    return sum([x * y for x, y in zip(v_1, v_2)])
def _minus(v_1: list, v_2: list) -> int:
    return tuple(x - y for x, y in zip(v_1, v_2))
def _times(a: int, v: list) -> list:
    return tuple(a * x for x in v)

for vi in v[1:]:

    mi = [_length(vi, uj) / _length(uj, uj) for uj in u]
    uj = vi
    for k in [_times(mij, uj) for (mij, uj) in zip(mi,u)]:
        uj = _minus(uj, k)
    u.append(uj)
print(u)
print(round(u[3][1], 5))
```
### 2. Gaussian Reduction

---

**_TASK:_**

```txt

v = (846835985, 9834798552), u = (87502093, 123094980) and by applying Gauss's algorithm, find the optimal basis. The flag is the inner product of the new basis vectors.
```

```py

Loop
   (a) If ||v2|| < ||v1||, swap v1, v2
   (b) Compute m = ⌊ v1∙v2 / v1∙v1 ⌉
   (c) If m = 0, return v1, v2
   (d) v2 = v2 - m*v1
Continue Loop
```

---

hmm bài này cũng khá dễ mình có sử dụng code của bài trước để tiết kiệm thời gian.

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/ab0a6855-8d36-4ed2-900f-4b6019f898d4)

Đây là thuật toán để đưa hai cơ sở (nhấn mạnh là hai vì nó không thực hiện khi có chiều khác) thành cơ sở gắn (không phải là gắn nhất) và gần như trực giao với nhau( tức đưa về thành hai vector gần vuông góc và có độ dài ngắn) theo mình thấy thì nó không có tác dụng nhiều vì mình đã có thuật toán khác mạnh hơn là LLL rồi. Có thể đọc qua ở [đây](https://en.wikipedia.org/wiki/Lattice_reduction)

```py

v = (846835985, 9834798552)
u = (87502093, 123094980)

def _length(v_1 : list, v_2) -> int:
    return sum([x * y for x, y in zip(v_1, v_2)])
def _minus(v_1: list, v_2: list) -> int:
    return tuple(x - y for x, y in zip(v_1, v_2))
def _times(a: int, v: list) -> list:
    return tuple(a * x for x in v)

m = 0

if _length(v, v) < _length(u, u):
    u, v= v, u
while True:

    m = round(_length(u, v)/ _length(u, u))

    if m == 0: 
        print(f"find solution: {v = }, {u = }")
        break
    
    v = _minus(v, _times(m, u))

print(f"Flag is {_length((-4053281223, 2941479672), (87502093, 123094980)) = }")
```
### 3. Find the lattice

---

**_TASK:_**
```py
from Crypto.Util.number import getPrime, inverse, bytes_to_long
import random
import math

FLAG = b'crypto{?????????????????????}'


def gen_key():
    q = getPrime(512)
    upper_bound = int(math.sqrt(q // 2))
    lower_bound = int(math.sqrt(q // 4))
    f = random.randint(2, upper_bound)
    while True:
        g = random.randint(lower_bound, upper_bound)
        if math.gcd(f, g) == 1:
            break
    h = (inverse(f, q)*g) % q
    return (q, h), (f, g)


def encrypt(q, h, m):
    assert m < int(math.sqrt(q // 2))
    r = random.randint(2, int(math.sqrt(q // 2)))
    e = (r*h + m) % q
    return e


def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m


public, private = gen_key()
q, h = public
f, g = private

m = bytes_to_long(FLAG)
e = encrypt(q, h, m)

print(f'Public key: {(q,h)}')
print(f'Encrypted Flag: {e}')
```

**_OUTPUT:_**

```txt
Public key: (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
Encrypted Flag: 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523
```

---

hmm. Bài này mình có ý tưởng dựa vào $e = r * h + m \pmod{q}$ nhưng không biết code kiểu gì.
Nên mình quay sang hướng $h = f ^ {-1} * g \pmod{q}$ $\to$ $h * f = g \pmod{q}$ $\to$ $f * h - g - k * q = 0$ từ đó mình xây dựng lattice như sau:
+ [[h, 1], [q, 0]] thỏa mãn điều kiện trên

mà ta dễ thấy nó có nghiệm là [f, -k] mà nó thường rất nhỏ(hmmm) nên ta đưa nó về bài toán vector ngắn nhất. Từ đó mình sử dụng LLL để đưa cơ sở trên thành cơ sở đơn giản hơn và sẽ đưa cho chúng ta g, f.

```sage

key = (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
enc = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523
q = key[0]
h = key[1]

M = Matrix([[h, 1], [q, 0]])
M = M.LLL()
def decrypt(q, h, f, g, e):
    a = (f * e) % q
    m = (a * pow(f, -1, g)) % g
    return m

g = M[0][0]
f = M[0][1]

print(bytes.fromhex(hex(decrypt(q, h, f, g, enc))[2:]))
```

### 4. Broken RSA

---
**_SOURCE:_**
```py
n = 27772857409875257529415990911214211975844307184430241451899407838750503024323367895540981606586709985980003435082116995888017731426634845808624796292507989171497629109450825818587383112280639037484593490692935998202437639626747133650990603333094513531505209954273004473567193235535061942991750932725808679249964667090723480397916715320876867803719301313440005075056481203859010490836599717523664197112053206745235908610484907715210436413015546671034478367679465233737115549451849810421017181842615880836253875862101545582922437858358265964489786463923280312860843031914516061327752183283528015684588796400861331354873
e = 16
ct = 11303174761894431146735697569489134747234975144162172162401674567273034831391936916397234068346115459134602443963604063679379285919302225719050193590179240191429612072131629779948379821039610415099784351073443218911356328815458050694493726951231241096695626477586428880220528001269746547018741237131741255022371957489462380305100634600499204435763201371188769446054925748151987175656677342779043435047048130599123081581036362712208692748034620245590448762406543804069935873123161582756799517226666835316588896306926659321054276507714414876684738121421124177324568084533020088172040422767194971217814466953837590498718

```


---

Đây là một bài mà hồi KCSC tranning mình vẫn chưa làm được mặc dù đã có hướng và gợi ý từ anh Tuệ(bây giờ vẫn đang tranning :? )

Ban đầu mình dùng thặng dư bậc 2 để tìm lại m như sau:

$$m ^ {16} = e \pmod{n}$$

sau khi tìm thặng dư bậc hai thì mình sẽ có:

$$m ^ 8 = a \pmod{n} \quad \to \quad m ^ 4 = b \pmod{q} ...$$

cứ tương tự như vậy mình sẽ tìm lại được m. Mình đã thử viết code tìm thặng dư bậc hai nhưng có vẻ nó hơi khó với mình và mình khá lười nên mình thay đổi hướng.

Dựa vào ý tưởng bài no more basic math hồi recruitment thì mình tạo ra một phương  một ẩn rồi sử dụng hàm small_roots để tìm lại ma trận nghiệm của nó (maybe là như thế này bởi vì hiện tại mình cũng chưa hiểu ý tưởng của nó lắm) như vậy là xong bài này.

```sage

n = 27772857409875257529415990911214211975844307184430241451899407838750503024323367895540981606586709985980003435082116995888017731426634845808624796292507989171497629109450825818587383112280639037484593490692935998202437639626747133650990603333094513531505209954273004473567193235535061942991750932725808679249964667090723480397916715320876867803719301313440005075056481203859010490836599717523664197112053206745235908610484907715210436413015546671034478367679465233737115549451849810421017181842615880836253875862101545582922437858358265964489786463923280312860843031914516061327752183283528015684588796400861331354873
e = 16
ct = 11303174761894431146735697569489134747234975144162172162401674567273034831391936916397234068346115459134602443963604063679379285919302225719050193590179240191429612072131629779948379821039610415099784351073443218911356328815458050694493726951231241096695626477586428880220528001269746547018741237131741255022371957489462380305100634600499204435763201371188769446054925748151987175656677342779043435047048130599123081581036362712208692748034620245590448762406543804069935873123161582756799517226666835316588896306926659321054276507714414876684738121421124177324568084533020088172040422767194971217814466953837590498718

PR.<x> = PolynomialRing(Zmod(n))

f = x ^ 16 - ct

f = f.roots()
for x in f:
    print(bytes.fromhex(hex(x[0])[2:]))
```

### 5. No way back home

---

**_Source:_**

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
from Crypto.Util.number import getPrime, GCD, bytes_to_long, long_to_bytes, inverse
from random import randint

FLAG = b'crypto{????????????????????????????????}'

p, q = getPrime(512), getPrime(512)
n = p * q

# Alice side
v = (p * randint(1, n)) % n
k_A = randint(1, n)
while GCD(k_A, n) != 1:
    k_A = randint(1, n)
vka = (v * k_A) % n

# Bob side
k_B = randint(1, n)
while GCD(k_B, n) != 1:
    k_B = randint(1, n)
vkakb = (vka * k_B) % n

# Alice side
vkb = (vkakb * inverse(k_A, n)) % n

# Bob side
v_s = (vkb * inverse(k_B, n)) % n

# Alice side
key = sha256(long_to_bytes(v)).digest()
cipher = AES.new(key, AES.MODE_ECB)
m = pad(FLAG, 16)
c = cipher.encrypt(m).hex()

out = ""
out += f"p, q = ({p}, {q}) \n"
out += f"vka = {vka} \n"
out += f"vkakb = {vkakb} \n"
out += f"vkb = {vkb} \n"
out += f"c = '{c}' \n"
with open("out.txt", "w") as f:
    f.write(out)
```

**_Output:_**

```py
p, q = (10699940648196411028170713430726559470427113689721202803392638457920771439452897032229838317321639599506283870585924807089941510579727013041135771337631951, 11956676387836512151480744979869173960415735990945471431153245263360714040288733895951317727355037104240049869019766679351362643879028085294045007143623763) 
vka = 124641741967121300068241280971408306625050636261192655845274494695382484894973990899018981438824398885984003880665335336872849819983045790478166909381968949910717906136475842568208640203811766079825364974168541198988879036997489130022151352858776555178444457677074095521488219905950926757695656018450299948207 
vkakb = 114778245184091677576134046724609868204771151111446457870524843414356897479473739627212552495413311985409829523700919603502616667323311977056345059189257932050632105761365449853358722065048852091755612586569454771946427631498462394616623706064561443106503673008210435922340001958432623802886222040403262923652 
vkb = 6568897840127713147382345832798645667110237168011335640630440006583923102503659273104899584827637961921428677335180620421654712000512310008036693022785945317428066257236409339677041133038317088022368203160674699948914222030034711433252914821805540365972835274052062305301998463475108156010447054013166491083 
c = 'fef29e5ff72f28160027959474fc462e2a9e0b2d84b1508f7bd0e270bc98fac942e1402aa12db6e6a36fb380e7b53323' 
```

---

Bài này có thể nói là dễ nhất trong các bài mình làm. :)

Đây là kiểu bài thuộc dạng diffie-hellman chuyển khóa và sử dụng khóa đó để mã hóa AES. Nhưng vấn đề ở đây là ta đã biết quá nhiều từ A, B, đến secret nên bài này có thể dễ dàng làm được với một chút kiến thức toán.

có:

$$n = p * q, v = p * r$$

$$v_a = v * A, v_b = v * B$$

$$v_{secret} = v * A * B$$

cái mình cần tìm ở đây là v vì nó được sử dụng để mã hóa AES. Ta đã có $v_a, v_b, v_{secret}$ đề cho nên mình tính lại v như sau:

$$v = (v_a * v_b) / (v_{secret}) \pmod{n}$$

$$v = ((p * r * A) * (p * r * B)) / (p * r * A * B)  = p * r\pmod{n}$$

nhưng do $v_{secret}$ không khả nghich trên $Z_n$ nên mình chia nó cho p trước khi nghịch đảo thì nó sẽ tồn tại khả nghịch.

$$((v_a / p) * (v_b / p)) / (v_{secret} / p) \pmod{n / p}$$

$$((r * A) * ( r * B)) / (r * A * B)  = r\pmod{q}$$

từ đó mình có được r và có thể tìm lại $v = p * r$ và việc còn lại chỉ là viết code decrypt nó thôi ez.

```py

from Crypto.Cipher import AES
from hashlib import sha256
from Crypto.Util.number import long_to_bytes


p, q = (10699940648196411028170713430726559470427113689721202803392638457920771439452897032229838317321639599506283870585924807089941510579727013041135771337631951, 11956676387836512151480744979869173960415735990945471431153245263360714040288733895951317727355037104240049869019766679351362643879028085294045007143623763) 
vka = 124641741967121300068241280971408306625050636261192655845274494695382484894973990899018981438824398885984003880665335336872849819983045790478166909381968949910717906136475842568208640203811766079825364974168541198988879036997489130022151352858776555178444457677074095521488219905950926757695656018450299948207 
vkakb = 114778245184091677576134046724609868204771151111446457870524843414356897479473739627212552495413311985409829523700919603502616667323311977056345059189257932050632105761365449853358722065048852091755612586569454771946427631498462394616623706064561443106503673008210435922340001958432623802886222040403262923652 
vkb = 6568897840127713147382345832798645667110237168011335640630440006583923102503659273104899584827637961921428677335180620421654712000512310008036693022785945317428066257236409339677041133038317088022368203160674699948914222030034711433252914821805540365972835274052062305301998463475108156010447054013166491083 
c = 'fef29e5ff72f28160027959474fc462e2a9e0b2d84b1508f7bd0e270bc98fac942e1402aa12db6e6a36fb380e7b53323'

n = p * q

v = ((vka // p) * (vkb // p)) * pow(vkakb // p, -1, q) % q

key = sha256(long_to_bytes(v * p)).digest()
cipher = AES.new(key, AES.MODE_ECB)

print(cipher.decrypt(bytes.fromhex(c)))
```

### 6. Unencryptable

---

**_Source:_**

```py
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

DATA = bytes.fromhex("372f0e88f6f7189da7c06ed49e87e0664b988ecbee583586dfd1c6af99bf20345ae7442012c6807b3493d8936f5b48e553f614754deb3da6230fa1e16a8d5953a94c886699fc2bf409556264d5dced76a1780a90fd22f3701fdbcb183ddab4046affdc4dc6379090f79f4cd50673b24d0b08458cdbe509d60a4ad88a7b4e2921")
FLAG = b'crypto{??????????????????????????????????????}'

def gen_keypair():
    p = getPrime(512)
    q = getPrime(512)
    N = p*q
    e = 65537
    phi = (p-1)*(q-1)
    d = inverse(e,phi)
    return N,e,d


def encrypt(m,e,N):
    m_int = bytes_to_long(m)
    c_int = pow(m_int,e,N)
    if m_int == c_int:
        print('RSA broken!?')
        return None
    else:
        return c_int

N,e,d = gen_keypair()
N = 89820998365358013473897522178239129504456795742012047145284663770709932773990122507570315308220128739656230032209252739482850153821841585443253284474483254217510876146854423759901130591536438014306597399390867386257374956301247066160070998068007088716177575177441106230294270738703222381930945708365089958721

encrypted_data = encrypt(DATA,e,N)
encrypted_flag = encrypt(FLAG,e,N)

print(f'N = {hex(N)}')
print(f'e = {hex(e)}')
print(f'c = {hex(encrypted_flag)}')
```


```txt

Unblvr: ~ % python3 source.py
RSA broken!?
N = 0x7fe8cafec59886e9318830f33747cafd200588406e7c42741859e15994ab62410438991ab5d9fc94f386219e3c27d6ffc73754f791e7b2c565611f8fe5054dd132b8c4f3eadcf1180cd8f2a3cc756b06996f2d5b67c390adcba9d444697b13d12b2badfc3c7d5459df16a047ca25f4d18570cd6fa727aed46394576cfdb56b41
e = 0x10001
c = 0x5233da71cc1dc1c5f21039f51eb51c80657e1af217d563aa25a8104a4e84a42379040ecdfdd5afa191156ccb40b6f188f4ad96c58922428c4c0bc17fd5384456853e139afde40c3f95988879629297f48d0efa6b335716a4c24bfee36f714d34a4e810a9689e93a0af8502528844ae578100b0188a2790518c695c095c9d677b
```

---

Hmm bài này đã từng được Dũng hướng dẫn nhưng quên mất :l

khi nhìn vào hàm `encrypt(m,e,N)`

```py
def encrypt(m,e,N):
    m_int = bytes_to_long(m)
    c_int = pow(m_int,e,N)
    if m_int == c_int:
        print('RSA broken!?')
        return None
    else:
        return c_int
```

mình thấy khi $m ^ e \equiv m \pmod{n}$ thì hàm sẽ không trả lại giá trị mã hóa, nếu khác thì nó vẫn trả ra như bình thường.

nhìn vào file output mình nhận thấy kết quả của hàm `encrypted_data = encrypt(DATA,e,N)` không được trả ra nên từ đó mình có thể kết luận ${data} ^ {r} \equiv {data} \pmod{n}$ (ở đây mình tạm gọi data = m để thuận tiện cho việc viết và đọc)

có : $m ^ e = m \pmod{n} \quad \to \quad m ^ e - m = 0 \pmod{n}$

$$m * (m ^ {e - 1} - 1) = 0 \pmod{n}$$

mà mình cũng thấy $e - 1 = 2 ^ 16$ tức ta có $m * (m ^ {2 ^ {16}} - 1) = 0 \pmod{n}$ từ đó ta dùng hằng đẳng thức $x ^ 2 - 1 = (x + 1) * (x - 1)$ cho phương trình trên ta sẽ có

$$m * (m ^ 2 + 1) * (m ^ 4 + 1) * ... * (m ^ {2 ^ {15}} + 1) = 0 \pmod{n}$$

$$m * (m ^ 2 + 1) * (m ^ 4 + 1) * ... * (m ^ {2 ^ {15}} + 1) = k * n = k * p * q$$

từ đó mình thấy rằng vế phải có một phần tử tỷ lệ với p hoặc q tức gcd($(m ^ i + 1)$, N) = p vì p là số nguyên tố. Khi đó mình có thể tìm lại được p, q và dễ dàng hoàn thành bài này.

```py

from Crypto.Util.number import *
from math import log2, gcd

def main() -> None:

    N: int = 0x7fe8cafec59886e9318830f33747cafd200588406e7c42741859e15994ab62410438991ab5d9fc94f386219e3c27d6ffc73754f791e7b2c565611f8fe5054dd132b8c4f3eadcf1180cd8f2a3cc756b06996f2d5b67c390adcba9d444697b13d12b2badfc3c7d5459df16a047ca25f4d18570cd6fa727aed46394576cfdb56b41
    e: int = 0x10001
    c: int = 0x5233da71cc1dc1c5f21039f51eb51c80657e1af217d563aa25a8104a4e84a42379040ecdfdd5afa191156ccb40b6f188f4ad96c58922428c4c0bc17fd5384456853e139afde40c3f95988879629297f48d0efa6b335716a4c24bfee36f714d34a4e810a9689e93a0af8502528844ae578100b0188a2790518c695c095c9d677b
    data: int = int("372f0e88f6f7189da7c06ed49e87e0664b988ecbee583586dfd1c6af99bf20345ae7442012c6807b3493d8936f5b48e553f614754deb3da6230fa1e16a8d5953a94c886699fc2bf409556264d5dced76a1780a90fd22f3701fdbcb183ddab4046affdc4dc6379090f79f4cd50673b24d0b08458cdbe509d60a4ad88a7b4e2921", 16)

    for i in range(1, int(log2(e - 1))):
        tmp = (pow(data, 2 ** i, N) + 1 ) % N
        if isPrime(gcd(tmp, N)):
            p = gcd(tmp, N)
            q = N // p
            break

    assert p * q == N and isPrime(p) and isPrime(q)

    print(f"Flag: {long_to_bytes(pow(c, inverse(e, (p - 1) * (q - 1)), N))}")

if __name__ == "__main__":
    main()
```

### 7. Prime and Prejudice

---

**_SOURCE:_**

```py

#!/usr/bin/env python3

from utils import listener

FLAG = 'crypto{????????????????????????????????????}'


def generate_basis(n):
    basis = [True] * n
    for i in range(3, int(n**0.5)+1, 2):
        if basis[i]:
            basis[i*i::2*i] = [False]*((n-i*i-1)//(2*i)+1)
    return [2] + [i for i in range(3, n, 2) if basis[i]]


def miller_rabin(n, b):
    """
    Miller Rabin test testing over all
    prime basis < b
    """
    basis = generate_basis(b)
    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for b in basis:
        x = pow(b, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def lizzies_little_window(a, p):
    if p < 1 or a < 1:
        return "[*] Error: Please, I will only accept positive integers."
    if p.bit_length() <= 600:
        return "[*] Error: Of all the primes, you choose to send me one so small?"
    if p.bit_length() > 900:
        return "[*] Error: I do wonder what're you trying to prove with a prime so big?"
    if not miller_rabin(p, 64):
        return "[*] Error: Sir, do you know what a prime number is?"
    if p < a:
        return "[*] Error: I'm sorry, but your base must be coprime to p"
    x = pow(a, p-1, p)
    return f"[*] Success: You passed all my tests! Here's the first byte of my flag: {FLAG[:x]}"


class Challenge():
    def __init__(self):
        self.before_input = "Oh Mr. Darcy, send me your primes!\n"

    def challenge(self, your_input):
        if not 'prime' in your_input or not 'base' in your_input:
            return {"error": "Please send a prime and a base to the server."}

        p = your_input['prime']
        a = your_input['base']
        return {"Response": lizzies_little_window(a, p)}


listener.start_server(port=13385)

```


---

Bài này yêu cầu mình phải tìm số giả nguyên tố thỏa mãn hàm check số nguyên tố kia.

Mình đã cố nhưng khó quá, khi nào có trình cao hơn qua lại sau.

[hint](https://eprint.iacr.org/2018/749.pdf)

[hint](https://math.stackexchange.com/questions/1528789/generating-false-positives-to-the-rabin-miller-primality-test)

```py

from Crypto.Util.number import *
from pwn import *
from json import *

def main() -> None:

    n = 254615674198066111348559108472798769684001878358857095506953165173728617744160791637392778869123081942910652286182625202904553164094373753256627211722903336405144072652128620402472907

    s = connect("socket.cryptohack.org", 13385)
    print(s.recvline())
    s.sendline(dumps({
        "prime": n,
        "base": 240133843331243659724883651873564602171659784123766621731827
    }).encode())

    print(s.recvline())
        


        

if __name__ == "__main__":
    main() 
```

### 8. Cofactor Cofantasy

----

**_Source:_**

```py
from utils import listener
from Crypto.Random.random import randint

FLAG = b"crypto{???????????????????????????????????}"

# N is a product of safe primes
N = 56135841374488684373258694423292882709478511628224823806418810596720294684253418942704418179091997825551647866062286502441190115027708222460662070779175994701788428003909010382045613207284532791741873673703066633119446610400693458529100429608337219231960657953091738271259191554117313396642763210860060639141073846574854063639566514714132858435468712515314075072939175199679898398182825994936320483610198366472677612791756619011108922142762239138617449089169337289850195216113264566855267751924532728815955224322883877527042705441652709430700299472818705784229370198468215837020914928178388248878021890768324401897370624585349884198333555859109919450686780542004499282760223378846810870449633398616669951505955844529109916358388422428604135236531474213891506793466625402941248015834590154103947822771207939622459156386080305634677080506350249632630514863938445888806223951124355094468682539815309458151531117637927820629042605402188751144912274644498695897277
phi = 56135841374488684373258694423292882709478511628224823806413974550086974518248002462797814062141189227167574137989180030483816863197632033192968896065500768938801786598807509315219962138010136188406833851300860971268861927441791178122071599752664078796430411769850033154303492519678490546174370674967628006608839214466433919286766123091889446305984360469651656535210598491300297553925477655348454404698555949086705347702081589881912691966015661120478477658546912972227759596328813124229023736041312940514530600515818452405627696302497023443025538858283667214796256764291946208723335591637425256171690058543567732003198060253836008672492455078544449442472712365127628629283773126365094146350156810594082935996208856669620333251443999075757034938614748482073575647862178964169142739719302502938881912008485968506720505975584527371889195388169228947911184166286132699532715673539451471005969465570624431658644322366653686517908000327238974943675848531974674382848
g = 986762276114520220801525811758560961667498483061127810099097

def get_bit(i):
    if FLAG[i // 8] & (1 << (i % 8)):
        return pow(g, randint(2, phi - 1), N)
    else:
        return randint(1, N - 1)

class Challenge():
    def __init__(self):
        self.before_input = "Is this real life, or is it just overly complicated math?\n"

    def challenge(self, your_input):
        if "option" not in your_input:
            return {"error": "Your input should contain an option"}
        if your_input["option"] == "get_bit":
            if "i" not in your_input:
                return {"error": "Open your eyes, look up to the skies and see: there's no bit index here."}
            i = int(your_input["i"])
            if not 0 <= i < 8*len(FLAG):
                return {"error": "This bit is a little high or a little low."}
            return {"bit": hex(get_bit(i))}
        else:
            return {"error": "I'm just a poor boy from a poor fantasy, I don't know how to do that."}


listener.start_server(port=13398)
```

----

Bài này mình có cố gắng làm nhưng k được:

Mình thấy có hai cách chính để làm bài này:
+ c1: dựa vào tính chất toán học
+ c2: timming attack (khá hay nên học hỏi)

C1:

Mình thấy hàm

```py
def get_bit(i):
    if FLAG[i // 8] & (1 << (i % 8)):
        return pow(g, randint(2, phi - 1), N)
    else:
        return randint(1, N - 1)
```

trả về các ký tự ngẫu nhiên mỗi khi ta gọi. Nếu

+ bit_i = 1 -> return $g ^ r \pmod{n}$ r là số random thuộc khoảng [2, phi -1]
+ bit_i = 0 -> return $r$ với r là số random thuộc khoảng [1, N - 1]

từ đó ta thấy có 50% khả năng r là số chẵn từ đó ta có $g ^ {2 * r / 2} \pmod{n}$ từ đó $g ^ {r / 2}$ là thặng dư bậc hai trong mod n.

Mình gửi nhiều lần yêu cầu get_bit tại một vị trí nếu có trường hợp nó trả ra một số thỏa mãn thặng dư bậc hai thì ta có thể kết luận bit tại đó là 1. Còn trường hợp nếu sau nhiều lần mà vẫn không thỏa mãn thì đó khả năng cao là bit 0 vì vẫn có trường hợp random ra các số lẻ liên tục (Nhưng ta có thể cải thiện bằng cách gửi đi nhiều lần hơn). Cứ làm như vậy đến khi biết hết các bit của flag.


```py

from Crypto.Random.random import randint
from factordb.factordb import FactorDB
from pwn import *
from json import *
from Crypto.Util.number import *

def check_bit(n: int, factors: int) -> bool:

    for factor in factors:

        if pow(n, (factor - 1) // 2, factor) != 1:
            return False
    
    return True

def main() -> None:

    N = 56135841374488684373258694423292882709478511628224823806418810596720294684253418942704418179091997825551647866062286502441190115027708222460662070779175994701788428003909010382045613207284532791741873673703066633119446610400693458529100429608337219231960657953091738271259191554117313396642763210860060639141073846574854063639566514714132858435468712515314075072939175199679898398182825994936320483610198366472677612791756619011108922142762239138617449089169337289850195216113264566855267751924532728815955224322883877527042705441652709430700299472818705784229370198468215837020914928178388248878021890768324401897370624585349884198333555859109919450686780542004499282760223378846810870449633398616669951505955844529109916358388422428604135236531474213891506793466625402941248015834590154103947822771207939622459156386080305634677080506350249632630514863938445888806223951124355094468682539815309458151531117637927820629042605402188751144912274644498695897277
    phi = 56135841374488684373258694423292882709478511628224823806413974550086974518248002462797814062141189227167574137989180030483816863197632033192968896065500768938801786598807509315219962138010136188406833851300860971268861927441791178122071599752664078796430411769850033154303492519678490546174370674967628006608839214466433919286766123091889446305984360469651656535210598491300297553925477655348454404698555949086705347702081589881912691966015661120478477658546912972227759596328813124229023736041312940514530600515818452405627696302497023443025538858283667214796256764291946208723335591637425256171690058543567732003198060253836008672492455078544449442472712365127628629283773126365094146350156810594082935996208856669620333251443999075757034938614748482073575647862178964169142739719302502938881912008485968506720505975584527371889195388169228947911184166286132699532715673539451471005969465570624431658644322366653686517908000327238974943675848531974674382848
    g = 986762276114520220801525811758560961667498483061127810099097
    FLAG = b"crypto{???????????????????????????????????}"
    flag = [0 for i in range(len(FLAG))]

    s = FactorDB(N)
    s.connect()

    factors = s.get_factor_list()
    
    s = connect("socket.cryptohack.org", 13398)
    print(s.recvuntil(b"\n"))

    for i in range(8 * len(FLAG)):

        print(flag)
        print(f"i = {i}")

        for _ in range(15):

            s.sendline(dumps({
                "option": "get_bit",
                "i": i
            }).encode())

            response = loads(s.recvline())["bit"]

            if check_bit(int(response[2:], 16), factors):
                flag[i // 8] += (1 << (i % 8))
                break

if __name__ == "__main__":
    main()
```

C2:

Mình dễ thấy tốc độ tính toán phép mũ và random nhỏ hơn mỗi lần random nên từ đó thời gian trả về của bit 0 và bit 1 là khác nhau ta có thể dựa vào thời gian đó để tìm lại được flag.

```py


from pwn import *
from json import *
import time
from Crypto.Util.number import *

def calculate_time(lst: list) -> str:

    min_time = min(lst)
    max_time = max(lst)

    label = ""
    for i in lst:

        if abs(i - min_time) < abs(i - max_time):
            label += "0"
        else:
            label += "1"
    return long_to_bytes(int(label, 2))

def main() -> None:
    
    recursion: int = 5
    FLAG = b"crypto{???????????????????????????????????}"

    s = connect("socket.cryptohack.org", 13398)

    s.recvuntil(b"\n")

    for i in range(0, 8 * len(FLAG), 8):

        part = []
        for j in range(8):
            
            tmp = []
            for _ in range(recursion):

                start = time.time()
              Real

---

**_Source:_**
```py
import math
from decimal import *
getcontext().prec = 100

FLAG = "crypto{???????????????}"
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103]

h = Decimal(0.0)

for i, c in enumerate(FLAG):
    h += ord(c) * Decimal(PRIMES[i]).sqrt()

ct = math.floor(h*16**64)
print(f"ciphertext: {ct}")

# ciphertext: 1350995397927355657956786955603012410260017344805998076702828160316695004588429433
```

---

Bài này khá hay, nó có nói về một kiến thức quan trọng trong toán đại số đó chính là không gian vector và cơ sở.

Mình tóm gọn lại đề bài như sau:

$$\sum_{i = 0} ^ {len(flag)} {flag[i]* PRIMES[i] * (16 ^ {64})}  = h$$

Từ đó mình xây dựng lại lattice như sau:

```py
[1 0 0 ... primes[0]]
[0 1 0 ... primes[1]]
...
[0 0 0 ... primes[n]]
[0 0 0 ...  0   h   ]
```

Xong rồi mình sử dụng LLL để đưa lattice trên về cơ sở gắn nhất trực giao với nhau và tìm lại flag ?

```py

PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103]
ciphertext=  1350995397927355657956786955603012410260017344805998076702828160316695004588429433

length = len(PRIMES)

M = [[0 for i in range(length + 1)] for y in  range(length + 1)]

for i in range(length):
    M[i][i] = 1
    M[i][-1] = round(sqrt(PRIMES[i]) * (16 ^ 64))

M[length][length] = ciphertext

M = Matrix(ZZ, M).LLL()
print(b"".join([bytes([-x]) if x < 0 else bytes([x]) for x in M[0]]))
```

### 10. Backpack Cryptography


---

**_Source:_**

```py
import random
from collections import namedtuple
import gmpy2
from Crypto.Util.number import isPrime, bytes_to_long, inverse, long_to_bytes

FLAG = b'crypto{??????????????????????????}'
PrivateKey = namedtuple("PrivateKey", ['b', 'r', 'q'])

def gen_private_key(size):
    s = 10000
    b = []
    for _ in range(size):
        ai = random.randint(s + 1, 2 * s)
        assert ai > sum(b)
        b.append(ai)
        s += ai
    while True:
        q = random.randint(2 * s, 32 * s)
        if isPrime(q):
            break
    r = random.randint(s, q)
    assert q > sum(b)
    assert gmpy2.gcd(q,r) == 1
    return PrivateKey(b, r, q)


def gen_public_key(private_key: PrivateKey):
    a = []
    for x in private_key.b:
        a.append((private_key.r * x) % private_key.q)
    return a


def encrypt(msg, public_key):
    assert len(msg) * 8 <= len(public_key)
    ct = 0
    msg = bytes_to_long(msg)
    for bi in public_key:
        ct += (msg & 1) * bi
        msg >>= 1
    return ct


def decrypt(ct, private_key: PrivateKey):
    ct = inverse(private_key.r, private_key.q) * ct % private_key.q
    msg = 0
    for i in range(len(private_key.b) - 1, -1, -1):
         if ct >= private_key.b[i]:
             msg |= 1 << i
             ct -= private_key.b[i]
    return long_to_bytes(msg)


private_key = gen_private_key(len(FLAG) * 8)
public_key = gen_public_key(private_key)
encrypted = encrypt(FLAG, public_key)
decrypted = decrypt(encrypted, private_key)
assert decrypted == FLAG

print(f'Public key: {public_key}')
print(f'Encrypted Flag: {encrypted}')
```

---


Khi đọc đề trên ta thấy đây là loại mã hóa backpack của Merkle- Hellman

Đầu tiên tạo ra một chuỗi siêu tăng tức $ a_i \in A \forall a_i > \sum_{k = o} ^ {i} {a_k}$. Đây được gọi là khóa bí mật của nó.
Sau đó ta sẽ tìm một số nguyên tố p sao cho $p > \sum{A}$ là cơ số cả hệ mật. Tìm số k khác trong khoảng $2 < k < p$ và gcd(k, p) = 1 để tạo ra khóa công khai.

từ đó khóa công khai sẽ là $b_i = {a_i} * k \pmod{p}$.

Với plaintext là chuỗi nhị phân dạng m = [$m_0, m_1, ..., m_n$], và n phải nhỏ hơn hoặc bằng số phần tử của public key.

Ta sẽ mã hóa như sau : $c = \sum_{k = 0} ^ {n} {{b_ i} * m_i}$

và giải mã bằng cách tìm lại khóa bí mật như sau $a_i = {b_i} * k ^ {- 1} \pmod{p}$

sau đó sử dụng bài toán giải dãy siêu tăng(thường sử dụng thuật toán tham lam để giải) từ đó tìm ra lần lượt các bit của flag.

Từ đó ta thấy mã hóa này sử dụng mấu chốt chính là bài toán giải dãy siêu tăng(rất dễ) nhưng nếu dãy đấy bị xáo trộn lên thì nó sẽ trở thành bài toán khó.

Nhưng nó cũng để lộ ra một điểm yếu là việc các plaintext là các vector nhỏ nên mình có thể phá được bài toán này theo hướng lattice. Ta tạo ra một lattice từ các dự liệu đã biết rồi đưa nó về bài toán tìm vector gần nhất.

Mình xây dựng lattice như sau:

```py

[2 0 0 ... key[0]]
[0 2 0 ... key[1]]
...
[0 0 0 ... key[n]]
[1 1 1 ...  enc  ]
```

Hơi tiêc là mình cũng chưa hiêu rõ là tại sao lại xây dựng lattice như này mà không phải bài như bài trên.

```py
rom Crypto.Util.number import long_to_bytes

length = len(key)

I = identity_matrix(length)

I = 2 * I
I = I.insert_row(length, [ZZ(1) for _ in range(length)])
key.append(enc)

key = [[ZZ(x)] for x in key]
I = I.augment(Matrix(key))

M = Matrix(ZZ, I)
M = M.LLL()

for i in M:
    flag = long_to_bytes(int(''.join(str(k) for k in [1 if k == -1 else 0 for k in i][::-1]),2))
    if b'crypto' in flag:
        print(flag)
        break

```

### 11. Roll your Own

---
**_Source:_**


```py
from Crypto.Util.number import getPrime
import random
from utils import listener

FLAG = 'crypto{???????????????????????????????????}'

class Challenge():
    def __init__(self):
        self.no_prompt = True
        self.q = getPrime(512)
        self.x = random.randint(2, self.q)

        self.g = None
        self.n = None
        self.h = None

        self.current_step = "SHARE_PRIME"

    def check_params(self, data):
        self.g = int(data['g'], 16)
        self.n = int(data['n'], 16)
        if self.g < 2:
            return False
        elif self.n < 2:
            return False
        elif pow(self.g,self.q,self.n) != 1:
            return False
        return True

    def check_secret(self, data):
        x_user = int(data['x'], 16)
        if self.x == x_user:
            return True
        return False

    def challenge(self, your_input):
        if self.current_step == "SHARE_PRIME":
            self.before_send = "Prime generated: "
            self.before_input = "Send integers (g,n) such that pow(g,q,n) = 1: "
            self.current_step = "CHECK_PARAMS"
            return hex(self.q)

        if self.current_step == "CHECK_PARAMS":
            check_msg = self.check_params(your_input)
            if check_msg:
                self.x = random.randint(0, self.q)
                self.h = pow(self.g, self.x, self.n)
            else:
                self.exit = True
                return {"error": "Please ensure pow(g,q,n) = 1"}

            self.before_send = "Generated my public key: "
            self.before_input = "What is my private key: "
            self.current_step = "CHECK_SECRET"

            return hex(self.h)

        if self.current_step == "CHECK_SECRET":
            self.exit = True
            if self.check_secret(your_input):
                return {"flag": FLAG}
            else:
                return {"error": "Protocol broke somewhere"}

        else:
            self.exit = True
            return {"error": "Protocol broke somewhere"}


listener.start_server(port=13403)

```

---

Đây là một bài theo kiểu giao thức chuyển khóa Diffe-Hellman, ta phải gửi cặp số (g, n) sao cho thỏa mãn $g ^ p = 1 \pmod{n}$ và nó sẽ trả cho ta $g ^ x = h \pmod{n}$ và nhiệm vụ chính của ta là phải tìm lại x.

Ban đầu mình có hướng như sau:

```py
(2 ^ (p - 1)) ^ p = 1  pmod(p ** 2)
(2 ^ (p * (p - 1))) = 1 \pmod(p ** 2)
2 ^ (x * (p - 1)) = h \pmod(p ** 2)
2 ^ (x * (p - 1)) = h + k * p ** 2
2 ^ (xp - x) = h + k * p ** 2
2 * 2 ^ - x = h \pmod(p)
2 / h = 2 ^ x \pmod(p)

```
từ đó mình đưa về bài toán log rời rạc cơ sở 2 trường p. Mình nghĩ nó có thể khả thi nhưng discrete_log lại không ra được đáp án nên mình làm theo hướng khác như sau.

với g = p + 1, n = p ** 2

ta có: $g ^ p = (p + 1) ^ p = 1 + p ^ 2 = 1 \pmod{p ^ 2}$
ta có: $g ^ x = (p + 1) ^ x = 1 + p * x ^ 2 = h \pmod{p ^ 2}$

từ đó ta có thể dễ dàng tìm lại $x = (h - 1) / p$.

```py

from pwn import *
from json import *

def main() -> None:
     
    # socket.cryptohack.org 13403

    s = connect("socket.cryptohack.org", 13403)

    s.recvuntil(b"Prime generated: ")

    p = int(s.recvline()[3: -2], 16)

    s.recv()
    s.sendline(dumps({
        "g": hex(p + 1)[2:],
        "n": hex(p ** 2)[2:]
    }).encode())

    s.recvuntil(b": ")
    h = int(s.recvline()[3: -2], 16)

    t = ((h - 1) // p) % p ** 2
    s.send(dumps({
        "x": hex(t)[2:]
    }).encode())
    print(s.recvline())

if __name__ == "__main__":
    main()

```
