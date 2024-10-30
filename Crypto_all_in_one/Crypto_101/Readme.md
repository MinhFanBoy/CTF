

Table_of_contents
=================

### 1. ezMath

---

__**chall.py**__

```py
from Crypto.Util.number import *
from Crypto.Cipher import AES
import random,string
from secret import flag,y,x
def pad(x):
    return x+b'\x00'*(16-len(x)%16)
def encrypt(KEY):
    cipher= AES.new(KEY,AES.MODE_ECB)
    encrypted =cipher.encrypt(flag)
    return encrypted
D = 114514
assert x**2 - D * y**2 == 1
flag=pad(flag)
key=pad(long_to_bytes(y))[:16]
enc=encrypt(key)
print(f'enc={enc}')
#enc=b"\xce\xf1\x94\x84\xe9m\x88\x04\xcb\x9ad\x9e\x08b\xbf\x8b\xd3\r\xe2\x81\x17g\x9c\xd7\x10\x19\x1a\xa6\xc3\x9d\xde\xe7\xe0h\xed/\x00\x95tz)1\\\t8:\xb1,U\xfe\xdec\xf2h\xab`\xe5'\x93\xf8\xde\xb2\x9a\x9a"
```

---

#### 1. Tổng quan

+ Ta có:
```py
D = 114514
assert x**2 - D * y**2 == 1
key=pad(long_to_bytes(y))[:16]
```

+ Ta có flag được mã hóa bằng AES với key là y, nên chúng ta cần tìm lại y từ phương trình `x**2 - D * y**2 == 1` là ta có thể dễ dàng có lại flag.


#### 2. Solution

+ Có $x^2 - D * y^2 == 1 \to D = (x ^2 - 1) / (y ^ 2) \to \sqrt(D) \approx x / y$ nên từ đó mình cần tìm lại phân số lien tục của $\sqrt(D)$ là có thể tìm lại được x, y và từ đó là dễ dàng có flag.

#### 3. Code

```py

from sage.rings.continued_fraction import convergents
from Crypto.Util.number import *
from Crypto.Cipher import AES

def pad(x):
    return x+b'\x00'*(16-len(x)%16)
def encrypt(KEY, enc):
    cipher= AES.new(KEY,AES.MODE_ECB)
    return cipher.decrypt(enc)
F = RealField(1024)
D = 114514


for _, i in enumerate(continued_fraction(sqrt(D)).convergents()):
    print(_)
    x = int(i.numerator())
    y = int(i.denominator())

    if (x ** 2 - D * y ** 2) == 1:
        print(f'x={x}, y={y}')

        key=pad(long_to_bytes(y))[:16]
        enc=b"\xce\xf1\x94\x84\xe9m\x88\x04\xcb\x9ad\x9e\x08b\xbf\x8b\xd3\r\xe2\x81\x17g\x9c\xd7\x10\x19\x1a\xa6\xc3\x9d\xde\xe7\xe0h\xed/\x00\x95tz)1\\\t8:\xb1,U\xfe\xdec\xf2h\xab`\xe5'\x93\xf8\xde\xb2\x9a\x9a"
        print(encrypt(key, enc))

        exit()
```
### 2. ezRSA
---

__**chal.py**__

```py
from Crypto.Util.number import *
from secret import flag
m=bytes_to_long(flag)
p=getPrime(1024)
q=getPrime(1024)
n=p*q
phi=(p-1)*(q-1)
e=0x10001
c=pow(m,e,n)
leak1=pow(p,q,n)
leak2=pow(q,p,n)

print(f'leak1={leak1}')
print(f'leak2={leak2}')
print(f'c={c}')

"""
leak1=149127170073611271968182576751290331559018441805725310426095412837589227670757540743929865853650399839102838431507200744724939659463200158012469676979987696419050900842798225665861812331113632892438742724202916416060266581590169063867688299288985734104127632232175657352697898383441323477450658179727728908669
leak2=116122992714670915381309916967490436489020001172880644167179915467021794892927977272080596641785569119134259037522388335198043152206150259103485574558816424740204736215551933482583941959994625356581201054534529395781744338631021423703171146456663432955843598548122593308782245220792018716508538497402576709461
c=10529481867532520034258056773864074017027019578041866245400647840230251661652999709715919620810933437191661180003295923273655675729588558899592524235622728816065501918076120812236580344991140980991532347991252705288633014913479970610056845543523591324177567061948922552275235486615514913932125436543991642607028689762693617305246716492783116813070355512606971626645594961850567586340389705821314842096465631886812281289843132258131809773797777049358789182212570606252509790830994263132020094153646296793522975632191912463919898988349282284972919932761952603379733234575351624039162440021940592552768579639977713099971
"""
```

---

#### 1. Tổng quan

+ Đây là một bài RSA đơn giản và ta có 2 số được leak ra là $l_1 = p ^ q \pmod{n}$ và $l_2 = q ^ p \pmod{n}$

#### 2. Solution

+ Đặt $p = q + k$
$$
l_1 = q^{q + k} \bmod{n} \\
l_2 = (q + k)^q \bmod{n} \\
l_1 \cdot l_2 = q^{q + k} \cdot (q + k)^q = ((q + k) * (q)) ^q * q ^ k \bmod n \\
l_1 \cdot l_2 = ((q + k) * (q)) ^q * q ^ k + k * q * p \to l_1 \cdot l_2 = k_1 * q
$$

+ Ngoài ra ta cũng có:

$$
l_1 ^ 2 = q^{2 * (q + k)} \bmod{n} = q^{2 * (q + k)} + k * p * q = k_2 * q
$$

Vậy `gcd(` $l_1 \cdot l_2, l_1 ^ 2$ `)` = q

Từ đó ta có thể dễ ràng có lại flag.

#### 3. Code

```py
from Crypto.Util.number import long_to_bytes

l1 = 149127170073611271968182576751290331559018441805725310426095412837589227670757540743929865853650399839102838431507200744724939659463200158012469676979987696419050900842798225665861812331113632892438742724202916416060266581590169063867688299288985734104127632232175657352697898383441323477450658179727728908669
l2 = 116122992714670915381309916967490436489020001172880644167179915467021794892927977272080596641785569119134259037522388335198043152206150259103485574558816424740204736215551933482583941959994625356581201054534529395781744338631021423703171146456663432955843598548122593308782245220792018716508538497402576709461
c=10529481867532520034258056773864074017027019578041866245400647840230251661652999709715919620810933437191661180003295923273655675729588558899592524235622728816065501918076120812236580344991140980991532347991252705288633014913479970610056845543523591324177567061948922552275235486615514913932125436543991642607028689762693617305246716492783116813070355512606971626645594961850567586340389705821314842096465631886812281289843132258131809773797777049358789182212570606252509790830994263132020094153646296793522975632191912463919898988349282284972919932761952603379733234575351624039162440021940592552768579639977713099971


p = int(gcd(l1 ** 2, l2 * l1))
print(long_to_bytes(pow(c, pow(0x10001, -1, p - 1), p)))
```

### 3. RR

---

__*chal.py*__

```py
p = random_prime(1<<512)

with open("ffllaagg.txt", "rb") as f:
    flag = int.from_bytes(f.read().strip(), "big")
assert flag < p

a = randint(2, p-1)
b = randint(2, p-1)
x = randint(2, p-1)

def h():
    global a, b, x
    x = (a*x + b) % p
    return x

PR.<X> = PolynomialRing(GF(p))
f = h() + h()*X + h()*X**2 + h()*X**3 + h()*X**4 + h()*X**5
v_me_50 = [(i, f(i)) for i in range(1, 5)]

print(p)
print(v_me_50)
print(f(flag))

p = 8432316544210923620966806031040552674652729976238765323782536889706914762471638598119051165931563126522925761119650997703305509546949570434637437942542827
v_me_50 = [(1, 5237331460408741346823741966490617418367283531029963248255318507187035341590236835730694472064897540292182231844047116067936691956970631907605500080014355), (2, 5798977431976767515500795413771120575460553181185728489626756434911307088093739452469315524092208822863785429164219547384598943937099787390543171055679780), (3, 5030862375386942201139427367618716490378481408210696947331523552250206476805124204780313138835912303941204343248384742875319182761611109448446270069831113), (4, 4705360705603328842229554954026497175574981026785287316439514185860486128679614980330307863925942038530792583274904352630757089631411920876914529907563209)]
f_flag = 7251453750672416392395590357197330390627853878488142305852099080761477796591562813165554150640801022882531891827653530623183405183605476913024545431842867
```

---

#### 1. Tổng quan

+ Ta có:
```py

def h():
    global a, b, x
    x = (a*x + b) % p
    return x

PR.<X> = PolynomialRing(GF(p))
f = h() + h()*X + h()*X**2 + h()*X**3 + h()*X**4 + h()*X**5
```
f là một đa thức được định nghĩa trên trường GF(p) với p đã biết. Ngoài ra các hệ số được tính bằng hàm h(). Ta còn biết giá trị của đa thức tại các điểm [1 -> 5] và ta có giá trị `f(flag)`

#### 2. Solution

với 5 giá trị đã biết ta có thể tạo ra được 5 phương trình với 3 ẩn số a, b, x đáng ra ta phải sử dụng tính lại các giá trị trên nhưng mình sử dụng groebner basis để tìm lại cho nhanh. Khi đã tìm được các hệ số thì ta thay lại vào phương trình để tìm lại flag.

#### 3. Code

```py

from Crypto.Util.number import *

p = 8432316544210923620966806031040552674652729976238765323782536889706914762471638598119051165931563126522925761119650997703305509546949570434637437942542827
v_me_50 = [(1, 5237331460408741346823741966490617418367283531029963248255318507187035341590236835730694472064897540292182231844047116067936691956970631907605500080014355), (2, 5798977431976767515500795413771120575460553181185728489626756434911307088093739452469315524092208822863785429164219547384598943937099787390543171055679780), (3, 5030862375386942201139427367618716490378481408210696947331523552250206476805124204780313138835912303941204343248384742875319182761611109448446270069831113), (4, 4705360705603328842229554954026497175574981026785287316439514185860486128679614980330307863925942038530792583274904352630757089631411920876914529907563209)]
f_flag = 7251453750672416392395590357197330390627853878488142305852099080761477796591562813165554150640801022882531891827653530623183405183605476913024545431842867

def h():
    global a, b, x
    x = (a*x + b)
    return x

PR.<a, b, x> = PolynomialRing(GF(p))
h_ = [h() for _ in range(6)]
eqs =[]
for X, (i, f_i) in zip(range(1, 5), v_me_50):
    eqs.append(sum([_ * (i ** __) for (_, __) in (zip(h_, list(range(0, 6))))]) - f_i)

I = PR.ideal(eqs)
c = []
for i in I.groebner_basis():
    c.append(i.univariate_polynomial().change_ring(Zmod(p)).roots()[0][0])

a, b, x = c
def h():
    global a, b, x
    x = (a*x + b)
    return x
PR.<X> = PolynomialRing(GF(p))
f = h() + h()*X + h()*X**2 + h()*X**3 + h()*X**4 + h()*X**5 - f_flag

print(long_to_bytes(int(f.roots()[0][0])))
```

### 4. tranformation

---

__**chal.py**__

```py

#!/usr/bin/env python
# coding: utf-8



from Crypto.Util.number import *
from secret import Curve,gx,gy

# flag = "hgame{" + hex(gx+gy)[2:] + "}"

def ison(C, P):
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0

def add(C, P, Q):
    c, d, p = C
    u1, v1 = P
    u2, v2 = Q
    assert ison(C, P) and ison(C, Q)
    u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p
    v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p
    return (int(u3), int(v3))

def mul(C, P, m):
    assert ison(C, P)
    c, d, p = C
    B = bin(m)[2:]
    l = len(B)
    u, v = P
    PP = (-u, v)
    O = add(C, P, PP)
    Q = O
    if m == 0:
        return O
    elif m == 1:
        return P
    else:
        for _ in range(l-1):
            P = add(C, P, P)
        m = m - 2**(l-1)
        Q, P = P, (u, v)
        return add(C, Q, mul(C, P, m))

c, d, p = Curve

G = (gx, gy)
P = (423323064726997230640834352892499067628999846, 44150133418579337991209313731867512059107422186218072084511769232282794765835)
Q = (1033433758780986378718784935633168786654735170, 2890573833121495534597689071280547153773878148499187840022524010636852499684)
S = (875772166783241503962848015336037891993605823, 51964088188556618695192753554835667051669568193048726314346516461990381874317)
T = (612403241107575741587390996773145537915088133, 64560350111660175566171189050923672010957086249856725096266944042789987443125)
assert ison(Curve, P) and ison(Curve, Q) and ison(Curve, G)
e = 0x10001
print(f"eG = {mul(Curve, G, e)}")

# eG = (40198712137747628410430624618331426343875490261805137714686326678112749070113, 65008030741966083441937593781739493959677657609550411222052299176801418887407)


```
---

#### 1. Tổng quan

+ Đường cong Edwards twisted. Phương trình: `x² + y² = c²(1 + dx²y²)`
+ Các hàm chính:
    `ison()`: Kiểm tra một điểm có nằm trên đường cong
    `add()`: Cộng hai điểm trên đường cong
    `mul()`: Nhân vô hướng (scalar multiplication)
+ với `flag = "hgame{" + hex(gx+gy)[2:] + "}"` ta cần tìm lại điểm `G` khi biết `e * G`

#### 2. Solution

+ Để tìm lại `G` thì ta cần nhân `e * G` với `e ^ -1` nhưng để tính được `e ^ -1` thì ca tần phải tìm lại được order của đường cong trên.
+ Ngoài ra ta cũng chưa biết tham số của đường cong nên ta cần tìm lại các tham số từ 5 điểm được cho. Ở đây mình sử dụng groebner_basis cho dễ.
+ Vậy khi đã có được đường cong thì mình muốn tìm lại order bằng cách đưa nó về lại đường cong `Short_Weierstrass` nhưng lúc mình tìm hiểu thì mình không thấy có cách nào chuyển trực tiếp dạng `twisted_Edwards` sang cả nên mình phải đưa về `twisted_Edwards` -> `Montgomery` -> `Short_Weierstrass`

+ Cho đường cong `E: x²/c² + y²/c² = 1 + dx²y²/c⁴`. Đặt `X = x/c, Y = y/c`. Ta có: `X² + Y² = 1 + (dc⁴)X²Y²`. Đây chính là dạng chuẩn hóa với `d' = dc⁴, a = 1`
+ Đầu tiên ta có đường cong Twisted Edwards: `au² + v² = 1 + du²v² (mod p)`
Để chuyển sang Montgomery, ta thực hiện phép biến đổi tọa độ:
```
u, v ⟺ x = (1+v)/(1-v), y = u/x
```

+ Phương trình Edwards: `au² + ((x-1)/(x+1))² = 1 + du²((x-1)/(x+1))²`

```
Đặt y = u/x, ta có u = xy. 
a(xy)² + ((x-1)/(x+1))² = 1 + d(xy)²((x-1)/(x+1))²
a(xy)²(x+1)² + (x-1)² = (x+1)² + d(xy)²(x-1)²
(x+1)²(1 - ay²x²) = (x-1)²(1 - dy²x²)
(x² + 2x + 1)(1 - ay²x²) = (x² - 2x + 1)(1 - dy²x²)
```

$$
A = 2(a+d)/(a-d) \\
B = 4/(a-d)
$$

+ Montgomery dạng: `By² = x³ + Ax² + x (mod p)`, Weierstrass: `y² = x³ + ax + b (mod p)`
```
x → x' = x + A/3
y → y' = y

By² = (x + A/3)³ + A(x + A/3)² + (x + A/3)
(x + A/3)³ = x³ + Ax²/3 + A²x/9 + A³/27
A(x + A/3)² = Ax² + 2A²x/3 + A³/9
(x + A/3) = x + A/3

By² = x³ + (A + A/3)*x² + (A²/9 + 2A²/3 + 1)x + (A³/27 + A³/9 + A/3)
```

Để có dạng Weierstrass chuẩn y² = x³ + ax + b, Chia cả hai vế cho B và do hệ số của x² phải bằng 0

```
a = (B²*(1 - A²/3)) mod p
b = (B³A(2A²/9 - 1)/3) mod p
```

#### 3. Code

```py

from Crypto.Util.number import *
P = (423323064726997230640834352892499067628999846, 44150133418579337991209313731867512059107422186218072084511769232282794765835)
Q = (1033433758780986378718784935633168786654735170, 2890573833121495534597689071280547153773878148499187840022524010636852499684)
S = (875772166783241503962848015336037891993605823, 51964088188556618695192753554835667051669568193048726314346516461990381874317)
T = (612403241107575741587390996773145537915088133, 64560350111660175566171189050923672010957086249856725096266944042789987443125)
eG = (40198712137747628410430624618331426343875490261805137714686326678112749070113, 65008030741966083441937593781739493959677657609550411222052299176801418887407)
F.<c, d> = PolynomialRing(ZZ, 2)

lst = [P, Q, S, T]

eqs = [
    (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) for u, v in lst
]

I = F.ideal(eqs)
l = I.groebner_basis()

p = l[-1]
c_ = l[0].univariate_polynomial().change_ring(Zmod(p)).roots()[0][0]
d_ = l[1].univariate_polynomial().change_ring(Zmod(p)).roots()[0][0]

Curve = c_, d_, p 

def  twisted_Edwards_to_Montgomery(C):
    a, d, p = C
    A, B = (2 * (a + d) * pow(a - d, -1, p)) % p, (4 * pow(a - d, -1, p)) % p
    return (A, B, p)

def Montgomery_to_twisted_Edwards(C):
    A, B, p = C
    a, d = (A + 2) * pow(B, -1, p), (A - 2) * pow(B, -1, p)
    return (a, d, p)

def Montgomery_to_Short_Weierstrass(C):
    A, B, p = C
    a = (B ** 2) * (1 - A ** 2 * pow(3, -1, p)) % p
    b = B ** 3 * A * pow(3, -1, p) * (2 * A ** 2 * pow(9, -1, p) - 1) % p

    return a, b, p

def ison(C, P):
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0
def add(C, P, Q):
    c, d, p = C
    u1, v1 = P
    u2, v2 = Q
    assert ison(C, P) and ison(C, Q)
    u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p
    v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p
    return (int(u3), int(v3))

def mul(C, P, m):
    assert ison(C, P)
    c, d, p = C
    B = bin(m)[2:]
    l = len(B)
    u, v = P
    PP = (-u, v)
    O = add(C, P, PP)
    Q = O
    if m == 0:
        return O
    elif m == 1:
        return P
    else:
        for _ in range(l-1):
            P = add(C, P, P)
        m = m - 2**(l-1)
        Q, P = P, (u, v)
        return add(C, Q, mul(C, P, m))
e = 0x10001
c = c_
d = d_

aa = 1
dd = (d * c ** 4) % p

C_ = twisted_Edwards_to_Montgomery((aa, dd, p))
a, b, _ = Montgomery_to_Short_Weierstrass(C_)
k = EllipticCurve(Zmod(p), [a, b]).order()
k = pow(e, -1, k)
G = mul(Curve, eG, k)
print(G)
assert (mul(Curve, G, e)==eG)
flag = "hgame{" + hex(G[0]+G[1])[2:] + "}"
print(flag)
```

### 5. Happy new year

---

__**chall.py**__

```py

from Crypto.Util.number import *
from secret import flag, Curve

def happy(C, P):
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0

def new(C, P, Q):
    c, d, p = C
    u1, v1 = P
    u2, v2 = Q
    assert happy(C, P) and happy(C, Q)
    u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p
    v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p
    return (int(u3), int(v3))

def year(C, P, m):
    assert happy(C, P)
    c, d, p = C
    B = bin(m)[2:]
    l = len(B)
    u, v = P
    PP = (-u, v)
    O = new(C, P, PP)
    Q = O
    if m == 0:
        return O
    elif m == 1:
        return P
    else:
        for _ in range(l-1):
            P = new(C, P, P)
        m = m - 2**(l-1)
        Q, P = P, (u, v)
        return new(C, Q, year(C, P, m))

c, d, p = Curve

flag = flag.lstrip(b'SICTF{').rstrip(b'}')
l = len(flag)
l_flag, r_flag = flag[:l // 2], flag[l // 2:]

m1, m2 = bytes_to_long(l_flag), bytes_to_long(r_flag)
assert m1 < p and m2 < p

P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)

print(f'happy(C, P) = {happy(Curve, P)}')
print(f'happy(C, Q) = {happy(Curve, Q)}')

print(f'P = {P}')
print(f'Q = {Q}')

print(f'm1 * P = {year(Curve, P, m1)}')
print(f'm2 * Q = {year(Curve, Q, m2)}')


"""
happy(C, P) = True
happy(C, Q) = True
P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
m1 * P = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
m2 * Q = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933) 
"""
```

---

#### 1. Tổng quan

+ Bài này cũng tương tự như bài trước, ta cũng có một đường cong `twisted_Edwards` và các điểm thuộc đường cong nên ta phải tìm lại đường cong.
+ flag được chia làm 2 phần `m1, m2` và lấy mỗi phần nhân vô hướng với $m_1 \cdot P = m_1P, m_2 \cdot Q = m_2Q$, ta cần phải log rời rạc để tìm lại m1, m1

#### 2. Solution

+ https://en.wikipedia.org/wiki/Montgomery_curve
+ http://staff.ustc.edu.cn/~yiouyang/wangb-ouyang-hu-CJE.pdf
+ https://www-fourier.univ-grenoble-alpes.fr/mphell/doc-v5/conversion_weierstrass_edwards.html

sử dụng các tài liệu trên để tìm lại được các điểm trên đường cong tương ứng. Do order của curve khác nhỏ cà smooth nên ta có thể dễ dàng dlog bằng sage.

#### 3. Code

```py

from Crypto.Util.number import *

P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
mP = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
mQ = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933) 

F.<c, d> = PolynomialRing(ZZ, 2)

lst = [P, Q, mP, mQ]

eqs = [
    (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) for u, v in lst
]

I = F.ideal(eqs)
l = I.groebner_basis()

p = max(i for (i, j) in factor(l[-1], 2 ** 20))
c_ = (- sqrt(- (l[0].univariate_polynomial().change_ring(Zmod(p)).coefficients()[0] ) % p) % p)
d_ = (- (l[1].univariate_polynomial().change_ring(Zmod(p)).coefficients()[0] ) % p)

def twisted_Edwards_to_Montgomery(C):
    a, d, p = C
    A, B = (2 * (a + d) * pow(a - d, -1, p)) % p, (4 * pow(a - d, -1, p)) % p
    return (A, B, p)

def Montgomery_to_twisted_Edwards(C):
    A, B, p = C
    a, d = (A + 2) * pow(B, -1, p), (A - 2) * pow(B, -1, p)
    return (a, d, p)

def Montgomery_to_Short_Weierstrass(C):
    A, B, p = C
    # a = pow((B ** 2) * (1 - A ** 2 * pow(3, -1, p)), -1, p)
    # b = A * pow(B ** 3 * A * pow(3, -1, p) * (2 * A ** 2 * pow(9, -1, p) - 1), -1, p)
    a = ((3 - A ** 2) * pow(3 * B ** 2, -1, p)) % p
    b = ((2 * (A ** 3) - 9 * A) * pow(27 * B ** 3, -1, p)) % p
    return a, b, p

def change_point_from_twisted_Edwards_to_Montgomery(P, C):
    a, d, p = C
    u, v = P
    x_, y_ = ((1 + v) * pow(1 - v, -1, p)) % p, ((1 + v) * pow((1 - v) * u, -1, p) % p) % p
    return int(x_) % p, int(y_) % p

def change_point_from_Montgomery_to_Short_Weierstrass(P, C):
    A, B, p = C
    x, y = P
    x_, y_ = ((x + A * pow(3, -1, p)) * pow(B, -1, p)) % p, (y * pow(B, -1, p)) % p
    return int(x_) % p, int(y_) % p

def is_on_twisted_Edwards(P, C):

    u, v = P
    a, d, p = C
    
    # Tính vế trái: au^2 + v^2
    left = (a * pow(u, 2, p) + pow(v, 2, p)) % p
    
    # Tính vế phải: 1 + du^2v^2
    right = (1 + d * pow(u, 2, p) * pow(v, 2, p)) % p
    
    return left - right

def is_on_Montgomery(P, C):

    x, y = P
    A, B, p = C

    left = (B * pow(y, 2, p)) % p

    right = (pow(x, 3, p) + A * pow(x, 2, p) + x) % p
    
    return left - right

def is_on_Short_Weierstrass(P, C):

    x, y = P
    a, b, p = C
    
    left = pow(y, 2, p)
    right = (pow(x, 3, p) + a * x + b) % p
    
    return left - right

p = 903968861315877429495243431349919213155709
c = 662698094423288904843781932253259903384619 # or p - c
d = 540431316779988345188678880301417602675534

Curve = 1, (d * pow(c, 4, p)), p 
M = twisted_Edwards_to_Montgomery(Curve)
W = Montgomery_to_Short_Weierstrass(M)
E = EllipticCurve(GF(p), W[:2])
P, Q, mP, mQ = [((i[0] * pow(c, -1, p)) % p, (i[1] * pow(c, -1, p)) % p) for i in (P, Q, mP, mQ)]
# print(is_on_twisted_Edwards(P, Curve), is_on_twisted_Edwards(Q, Curve), is_on_twisted_Edwards(mP, Curve), is_on_twisted_Edwards(mQ, Curve))

P = change_point_from_twisted_Edwards_to_Montgomery(P, Curve)
Q = change_point_from_twisted_Edwards_to_Montgomery(Q, Curve)
mP = change_point_from_twisted_Edwards_to_Montgomery(mP, Curve)
mQ = change_point_from_twisted_Edwards_to_Montgomery(mQ, Curve)

# print(is_on_Montgomery(P, M), is_on_Montgomery(Q, M), is_on_Montgomery(mP, M), is_on_Montgomery(mQ, M))
P = change_point_from_Montgomery_to_Short_Weierstrass(P, M)
Q = change_point_from_Montgomery_to_Short_Weierstrass(Q, M)
mP = change_point_from_Montgomery_to_Short_Weierstrass(mP, M)
mQ = change_point_from_Montgomery_to_Short_Weierstrass(mQ, M)

P = E(P)
Q = E(Q)
mP = E(mP)
mQ = E(mQ)

m1 = int(discrete_log(mP, P, operation = "+"))
m2 = int(discrete_log(mQ, Q, operation = "+"))
print(long_to_bytes(m1) + long_to_bytes(m2))

```
