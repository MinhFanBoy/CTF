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


