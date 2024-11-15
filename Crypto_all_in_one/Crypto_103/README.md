
Table_of_contents
=================


### 1. baby

---
**__chall.py__**

```py
from secret import flag
from Crypto.Util.number import *
m = bytes_to_long(flag)
p = getPrime(512)
q = getPrime(512)
n = p*q
c = pow(m, 65537, n)
N = getPrime(1024)
leak = (pow(9999, 66666)*p + pow(66666, 9999)*q) % N
print(f'n={n}')
print(f'c={c}')
print(f'N={N}')
print(f'leak={leak}')
"""
n=80916351132285136921336714166859402248518125673421944066690210363157948681543515675261790287954711843082802283188843248579293238274583917836325545166981149125711216316112644776403584036920878846575128588844980283888602402513345309524782526525838503856925567762860026353261868959895401646623045981393058164201
c=22730301930220955810132397809406485504430998883284247476890744759811759301470013143686059878014087921084402703884898661685430889812034497050189574640139435761526983415169973791743915648508955725713703906140316772231235038110678219688469930378177132307304731532134005576976892978381999976676034083329527911241
N=175887339574643371942360396913019735118423928391339797751049049816862344090324438786194807609356902331228801731590496587951642499325571035835790931895483345540104575533781585131558026624618308795381874809845454092562340943276838942273890971498308617974682097511232721650227206585474404895053411892392799799403
leak=161177488484579680503127298320874823539858895081858980450427298120182550612626953405092823674668208591844284619026441298155371399651438065337570099147890081125477609238234662000811899869636390550619251741676887565983189442613760093303841954633720778312454175652907352477365434215186845209831284593041581382419
"""
```

---

#### 1. Tổng quan

+ Mình có đây là một bài `RSA` bình thường với các tham số như sau:
    + `p` và `q` đều là `getPrime(512)` nên n là một số lớn khó có thể factor
    + Ta còn có `leak = (pow(9999, 66666)*p + pow(66666, 9999)*q) % N` với `N = getPrime(1024)`

#### 2. Solution

+ Mình thấy bài này khá đơn giản khi ta có thể coi ${leak} = {9999 ^ {66666}} * p + {66666 ^ {9999}} * q \pmod{N}$ trong đó ta đã biết $n = p * q$ ta chỉ cần nhân `p` hoặc `q` vào lại phương trình trên là ta có ${leak} * q = {9999 ^ {66666}} * p * q + {66666 ^ {9999}} * q * q\pmod{N} \to {66666 ^ {9999}} * {q ^ 2} - {leak} * q - {9999 ^ {66666}} * n \pmod{N}$ đây chỉ còn là phương trình một ẩn trong trương GF(p) nên ta có thể dễ dàng dùng hàm `roots()` để giải, từ đó ta có lại `p` và dễ dàng hoàn thành bài này.

#### 3. Code

```py

from Crypto.Util.number import *

n=80916351132285136921336714166859402248518125673421944066690210363157948681543515675261790287954711843082802283188843248579293238274583917836325545166981149125711216316112644776403584036920878846575128588844980283888602402513345309524782526525838503856925567762860026353261868959895401646623045981393058164201
c=22730301930220955810132397809406485504430998883284247476890744759811759301470013143686059878014087921084402703884898661685430889812034497050189574640139435761526983415169973791743915648508955725713703906140316772231235038110678219688469930378177132307304731532134005576976892978381999976676034083329527911241
N=175887339574643371942360396913019735118423928391339797751049049816862344090324438786194807609356902331228801731590496587951642499325571035835790931895483345540104575533781585131558026624618308795381874809845454092562340943276838942273890971498308617974682097511232721650227206585474404895053411892392799799403
leak=161177488484579680503127298320874823539858895081858980450427298120182550612626953405092823674668208591844284619026441298155371399651438065337570099147890081125477609238234662000811899869636390550619251741676887565983189442613760093303841954633720778312454175652907352477365434215186845209831284593041581382419

F.<p, q> = PolynomialRing(Zmod(N))

f = [
    p * q - n,
    leak - (pow(9999, 66666, N) * p + pow(66666, 9999, N) * q)
]

I = F.ideal(f)
for i in I.groebner_basis():
    try:
        l = (i.univariate_polynomial().change_ring(Zmod(N)).roots())
        # l = [(126371379019665394439927893894333235509921065681626125681010103427245050888149502812747360388828767184621165920658938845936907847295615412901535775487711595141520676828617499979848667703207396985330950644703802868039752167789436623317822137739749488682832458290616162950292983580549023267195041313364998419323, 1), (10979956285614372224827660200211864819021686868896320580466122158997232847951270943442231337349648851036639259955523675922303039702618471186902785575831101, 1)]

        for q, _ in l:
            p = n // q
            print(long_to_bytes(int(pow(c, pow(65537, -1, (p - 1) * (q - 1)), n))))
    except:
        pass
```

### 2. RSA

---
**__chall.py__**
```py
from Crypto.Util.number import *
from secret import flag
z = 567
p = getPrime(1024)
q = getPrime(1024)
n = p*q
c = pow(bytes_to_long(flag), 65537, n)
tot = (p-1) * (q-1)
d = int(pow(65537, -1, tot))
dinv = int(pow(d, -1, n))

h = int(dinv >> z)
hpq = (int((p+q)>> z))

with open('out.txt', 'w+') as f:
    f.write(f'{n=}\n')
    f.write(f'{h=}\n')
    f.write(f'{hpq=}\n')
    f.write(f'{c=}\n')
```


**__output.txt__**

```py
n=13986357905153484822874300783445968480194277882812317554826224241536479785567487956712558237728345348661360577246137576216953724039680969623887884690471844396542763308129517234365819619617071449273126659007918716307793788623728052337632935762139796688014791419718949572448772521789488223910450877828732015095423443037519388747356327730350934152781671783952028215703864406564741666179193772037496984854699143314813242721157017296866888522135989818414587193505121794302821401677072507471357592358012342178011963104524959087968374300060349343826214249928530346877968114749229074874962737714935221065368318487049394644831
h=10474216468878927114435400909130676124750910912012236182806861194655854223324539867768381265996955193355030239325750528328250897464859373863289680002879536341349759323910048168674147097644573874679268018966497862685092382336865554114348153248267599439087357199554652601126191061921516650448119261614064051599968120061991607030873881013657693987836636730528537557619595799676312850875727477092697270452300532360780188724484703363561848754770976459
hpq=492124417091708682668644108145880307537308922842816506360717440112116492381514432506339907757228214359689270777951081610062506962769167209
c=4715651972688371479449666526727240348158670108161494767004202259402013317642418593561463200947908841531208327599049414587586292570298317049448560403558027904798159589477994992384199008976859139072407664659830448866472863679123027179516506312536814186903687358198847465706108667279355674105689763404474207340186200156662095468249081142604074167178023479657021133754055107459927667597604156397468414872149353231061997958301747136265344906296373544580143870450924707559398134384774201700278038470171319329716930036843839101955981274793386611943442507144153946307781795085665793554799349509983282980591388585613674226899
```

---

#### 1. Tổng quan

+ Đây cũng là một bài `RSA` khá tương tự với bài trên với p, q là `getPrime(1024)` nên `n = q * p` là một số khó có thể factor :b
+ Ta có 2 hint như sau:
    + `h = int(dinv >> z)` với `dinv = int(pow(d, -1, n))`
    + `hpq = (int((p+q)>> z))`

#### 2. Solution

+ với `e = 65537` nên ta có:
    + $phi = (p-1) * (q-1) \to d = 65537 ^ {-1} \pmod{phi} \to 65537 * d = 1 \pmod{phi}$
    + ${dinv} = d ^ {-1} \pmod{n}$ -> $d * {dinv} = 1 \pmod{n}$
    
    -> $65537 * d * {dinv} = (1 + k * {phi}) * {dinv} = (1 + k * (- q - p + 1)) * {dinv} = 65537 \pmod{n}$

-> $(1 + k * (- (hpq << z + x_1) + 1)) * {(h << z + x_2)} = 65537 \pmod{n}$

Đến đây rồi thì mình sử dụng hàm Copper Smith hai ẩn để tìm lại $x_1, x_2$, từ đó có thể tìm lại phần còn thiếu của `p` và `q`. Phần còn lại trở nên quá đơn giản :v

#### 3. Code

```py


import itertools

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), 1)
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []

from Crypto.Util.number import long_to_bytes
n=13986357905153484822874300783445968480194277882812317554826224241536479785567487956712558237728345348661360577246137576216953724039680969623887884690471844396542763308129517234365819619617071449273126659007918716307793788623728052337632935762139796688014791419718949572448772521789488223910450877828732015095423443037519388747356327730350934152781671783952028215703864406564741666179193772037496984854699143314813242721157017296866888522135989818414587193505121794302821401677072507471357592358012342178011963104524959087968374300060349343826214249928530346877968114749229074874962737714935221065368318487049394644831
h=10474216468878927114435400909130676124750910912012236182806861194655854223324539867768381265996955193355030239325750528328250897464859373863289680002879536341349759323910048168674147097644573874679268018966497862685092382336865554114348153248267599439087357199554652601126191061921516650448119261614064051599968120061991607030873881013657693987836636730528537557619595799676312850875727477092697270452300532360780188724484703363561848754770976459
hpq=492124417091708682668644108145880307537308922842816506360717440112116492381514432506339907757228214359689270777951081610062506962769167209
c=4715651972688371479449666526727240348158670108161494767004202259402013317642418593561463200947908841531208327599049414587586292570298317049448560403558027904798159589477994992384199008976859139072407664659830448866472863679123027179516506312536814186903687358198847465706108667279355674105689763404474207340186200156662095468249081142604074167178023479657021133754055107459927667597604156397468414872149353231061997958301747136265344906296373544580143870450924707559398134384774201700278038470171319329716930036843839101955981274793386611943442507144153946307781795085665793554799349509983282980591388585613674226899
z = 567
e = 65537
F.<v, s, k> = PolynomialRing(Zmod(n), 3)

s_ = int(hpq << z) + s
v_ = int(h << z) + v
f = v_ + v_ * k * (- s_ + 1) - 65537
print(f)

# print(small_roots(f, [1 << z, 1 << z, e], m = 5, d = 3))
l = [(159317428074584792171997344108483581050021451241399585759794019226915430675361841023574400082059487418815574535911604507422689916359462402941833334486836853973877390626297, 297303128327821326269706242033007721856940009764552260111940622211183154806465019556911576015485644682804240833282329637063755835394160846528534760530690317329064904894848, 8790)]

phi = n - (hpq << z) - l[0][1] + 1

d = int(pow(e, -1, phi))
print(long_to_bytes(int(pow(c, d, n))))
```

### 3. gcccd

---

**__chall.py__**

```py

from Crypto.Util.number import getStrongPrime, GCD, bytes_to_long
import os
from flag import flag

def long_to_bytes(long_int, block_size=None):
    """Convert a long integer to bytes, optionally right-justified to a given block size."""
    bytes_data = long_int.to_bytes((long_int.bit_length() + 7) // 8, 'big')
    return bytes_data if not block_size else bytes_data.rjust(block_size, b'\x00')

def gen_keys(bits=512, e=5331):
    """Generate RSA modulus n and public exponent e such that GCD((p-1)*(q-1), e) == 1."""
    while True:
        p, q = getStrongPrime(bits), getStrongPrime(bits)
        n = p * q
        if GCD((p-1) * (q-1), e) == 1:
            return n, e

def pad(m, n):
    """Pad the message m for RSA encryption under modulus n using PKCS#1 type 1."""
    mb, nb = long_to_bytes(m), long_to_bytes(n)
    assert len(mb) <= len(nb) - 11
    padding = os.urandom(len(nb) - len(mb) - 3).replace(b'\x01', b'')
    return bytes_to_long(b'\x00\x01' + padding + b'\x00' + mb)

def encrypt(m, e, n):
    """Encrypt message m with RSA public key (e, n)."""
    return pow(m, e, n)

n, e = gen_keys()
m = pad(bytes_to_long(flag), n)
c1, c2 = encrypt(m, e, n), encrypt(m // 2, e, n)

print(f"n = {n}\ne = {e}\nc1 = {c1}\nc2 = {c2}")

# n = 128134155200900363557361770121648236747559663738591418041443861545561451885335858854359771414605640612993903005548718875328893717909535447866152704351924465716196738696788273375424835753379386427253243854791810104120869379525507986270383750499650286106684249027984675067236382543612917882024145261815608895379
# e = 5331
# c1 = 60668946079423190709851484247433853783238381043211713258950336572392573192737047470465310272448083514859509629066647300714425946282732774440406261265802652068183263460022257056016974572472905555413226634497579807277440653563498768557112618320828785438180460624890479311538368514262550081582173264168580537990
# c2 = 43064371535146610786202813736674368618250034274768737857627872777051745883780468417199551751374395264039179171708712686651485125338422911633961121202567788447108712022481564453759980969777219700870458940189456782517037780321026907310930696608923940135664565796997158295530735831680955376342697203313901005151
```

#### 1. Tổng quan

+ Bài này khá tương tự như bài trên, nó cho ta $m ^ e = c_1 \pmod{n}$ và ${(m / 2)} ^ e = c_2 \pmod{n}$

#### 2. Solution

+ Với $m // 2 = x$ thì ta dễ có $m = 2 * x$ hoặc $m = 2 * x + 1$ nên ta có thể suy ra:
    + $x ^ e = c_2 \pmod{n}$
    + ${2 * x + 1} ^ e = c_2 \pmod{n}$ hoặc ${2 * x} ^ e = c_2 \pmod{n}$
+ Do hai phương trình đều có nghiệm chung là $x$ nên ta có thể `gcd` để tìm lại giá trị `x`. Nhưng ở đây có một lưu ý đó là do `e` khá lớn nên việc `gcd` có thể rất lâu nên ta sử dụng `HGCD` để giúp tăng tốc độ tính toán.

#### 3. Code

```py

from Crypto.Util.number import *
import logging 
import sys

sys.setrecursionlimit(500000)

def HGCD(a, b):
    if 2 * b.degree() <= a.degree() or a.degree() == 1:
        return 1, 0, 0, 1
    m = a.degree() // 2
    a_top, a_bot = a.quo_rem(x^m)
    b_top, b_bot = b.quo_rem(x^m)
    R00, R01, R10, R11 = HGCD(a_top, b_top)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    q, e = c.quo_rem(d)
    d_top, d_bot = d.quo_rem(x^(m // 2))
    e_top, e_bot = e.quo_rem(x^(m // 2))
    S00, S01, S10, S11 = HGCD(d_top, e_top)
    RET00 = S01 * R00 + (S00 - q * S01) * R10
    RET01 = S01 * R01 + (S00 - q * S01) * R11
    RET10 = S11 * R00 + (S10 - q * S11) * R10
    RET11 = S11 * R01 + (S10 - q * S11) * R11
    return RET00, RET01, RET10, RET11
    
def GCD(a, b):
    print(f"._. --> : d_a = {a.degree()}, d_b = {b.degree()}")

    q, r = a.quo_rem(b)
    if r == 0:
        return b
    R00, R01, R10, R11 = HGCD(a, b)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    if d == 0:
        return c.monic()
    q, r = c.quo_rem(d)
    if r == 0:
        return d
    return GCD(d, r)

n = 128134155200900363557361770121648236747559663738591418041443861545561451885335858854359771414605640612993903005548718875328893717909535447866152704351924465716196738696788273375424835753379386427253243854791810104120869379525507986270383750499650286106684249027984675067236382543612917882024145261815608895379
e = 5331
c1 = 60668946079423190709851484247433853783238381043211713258950336572392573192737047470465310272448083514859509629066647300714425946282732774440406261265802652068183263460022257056016974572472905555413226634497579807277440653563498768557112618320828785438180460624890479311538368514262550081582173264168580537990
c2 = 43064371535146610786202813736674368618250034274768737857627872777051745883780468417199551751374395264039179171708712686651485125338422911633961121202567788447108712022481564453759980969777219700870458940189456782517037780321026907310930696608923940135664565796997158295530735831680955376342697203313901005151

R.<x> = PolynomialRing(Zmod(n))
g = (2 * x + 1) ^ e - c1
PR.<y> = R.quotient(g)

h = y^e - c2
f = h.lift()

res = GCD(f,g).monic().coefficients()[0]
print(long_to_bytes(int(2 * int(-res % n) + 1)))
```

### 4. Decision

---

**__chall.py__**

```py

from Crypto.Util.number import *
from random import *
from secret import flag
import string

class MRG:
    def __init__(self,para_len,p):
        self.init(para_len,p)

    def next(self):
        self.s = self.s[1:] + [(sum([i * j for (i, j) in zip(self.a, self.s)]) + self.b) % self.p]
        return self.s[-1]

    def init(self,para_len,p):
        self.p = p
        self.b = randint(1, self.p)
        self.a = [randint(1, self.p) for i in range(para_len)]
        self.s = [ord(choice(string.printable)) for i in range(para_len)]
    
    def get_params(self):
        return [self.a,self.b,self.s[0]]


flag = bytes_to_long(flag)
flag_bin = bin(flag)[2:]

Round = 2024
A_len = 10
p = getPrime(256)

output = []
for i in flag_bin:
    if(i == "0"):
        temp = MRG(A_len,p)
        for j in range(Round):
            temp.next()
        output.append(temp.get_params())
    else:
        a = [randint(1,p) for i in range(A_len)]
        b = randint(1,p)
        s = randint(1,p)
        output.append([a,b,s])

with open("output.txt","w") as f:
    f.write(str(p))
    f.write(str(output))

```

**__output.txt__**

```py
quá dài nên mình không cho vào đây
```
---

#### 1. Tổng quan

+ Ta có `flag = bytes_to_long(flag)` và `flag_bin = bin(flag)[2:]` nên flag được mã hóa thành các bit `0, 1`. Sau đó chương trình sẽ chạy qua từng bit trên, tùy thuộc vào bit của flag là `0` hay `1` thì chương trình sẽ chạy theo các hướng khác nhau:
    + Nếu bit = 0: Chương trình sẽ khởi tạo một hàm random và trả lại cho ta kết qur của hàm random sau `2024` lần chạy.
    ```py
            temp = MRG(A_len,p)
        for j in range(Round):
            temp.next()
        output.append(temp.get_params())
    ```

    + Nếu bit = 1: Chương trình sẽ trả cho ta có số ngẫu nhiên từ hàm thư viện.
    ```py
        a = [randint(1,p) for i in range(A_len)]
        b = randint(1,p)
        s = randint(1,p)
        output.append([a,b,s])
    ```
+ Về class `MRG`:
    + là một hàm random với đầu vào như sau:
    ```py
        self.p = getPrime(256)
        self.b = randint(1, self.p)
        self.a = [randint(1, self.p) for i in range(para_len)]
        self.s = [ord(choice(string.printable)) for i in range(para_len)]
    ``` 
    + sau mỗi lần chạy seed sẽ đều được cập nhật thêm và kết quả ta nhận được là giá trị seed đầu tiên
    ```py
        self.s = self.s[1:] + [(sum([i * j for (i, j) in zip(self.a, self.s)]) + self.b) % self.p]
        return self.s[-1]
    ```

#### 2. Solution

+ Để làm được bài này mình cần phải phân biệt đâu là kết quả của hàm `MRG` và đâu là kết quả của hàm hệ thống nên mình có nhìn vào `output` của hàm `MRG` và thấy:
    + `return self.s[-1]` kết quả mà ta nhận được là một giá trị của seed, ngoài ra seed còn được cập nhật thêm phần tử mới có giá trị `[(sum([i * j for (i, j) in zip(self.a, self.s)]) + self.b) % self.p]`

    s[-1] = $(\sum_{i=0}^{len(s)}{a_i * s_i}) + b$
    Từ đó ta có thể thấy các kết quả của hàm `MRG` trả ra đều tuyến tính. Do đã có đầu vào `a` được thử thách cung cấp và kết quả của hàm sau `2024` lần chạy mình có thể tìm lại được một phương trình tuyến tính với ẩn là một chuỗi seed và do `s = [ord(choice(string.printable)) for i in range(para_len)]` seed có giá trị rất nhỏ nên mình sử dụng `solve_linear_mod` để tìm lại seed

+ Ta cứ thử `solve_linear_mod` cho tưng kết quả đầu ra của bài. Nếu hàm trên không trả ra kết quả hoặc trả ra kết quả không nằm trong khoảng nghiệm trên thì ta có thể khẳng định cao đó là kết quả của hàm `random` mặc định và bit của flag tại đó là `1` và ngược lại. Cứ tiếp tục như vậy là ta có thể hoàn tất recover flag.

#### 3. Code

```py

from Crypto.Util.number import *
from random import *
import string

"""
Solve a bounded system of modular linear equations.

(c) 2019-2022 Robert Xiao <nneonneo@gmail.com>
https://robertxiao.ca

Originally developed in May 2019; updated July 2022

Please mention this software if it helps you solve a challenge!
"""

from collections.abc import Sequence
import math
import operator
from typing import List, Tuple
from sage.all import ZZ, gcd, matrix, prod, var


def _process_linear_equations(equations, vars, guesses) -> List[Tuple[List[int], int, int]]:
    result = []

    for rel, m in equations:
        op = rel.operator()
        if op is not operator.eq:
            raise TypeError(f"relation {rel}: not an equality relation")

        expr = (rel - rel.rhs()).lhs().expand()
        for var in expr.variables():
            if var not in vars:
                raise ValueError(f"relation {rel}: variable {var} is not bounded")

        # Fill in eqns block of B
        coeffs = []
        for var in vars:
            if expr.degree(var) >= 2:
                raise ValueError(f"relation {rel}: equation is not linear in {var}")
            coeff = expr.coefficient(var)
            if not coeff.is_constant():
                raise ValueError(f"relation {rel}: coefficient of {var} is not constant (equation is not linear)")
            if not coeff.is_integer():
                raise ValueError(f"relation {rel}: coefficient of {var} is not an integer")

            coeffs.append(int(coeff) % m)

        # Shift variables towards their guesses to reduce the (expected) length of the solution vector
        const = expr.subs({var: guesses[var] for var in vars})
        if not const.is_constant():
            raise ValueError(f"relation {rel}: failed to extract constant")
        if not const.is_integer():
            raise ValueError(f"relation {rel}: constant is not integer")

        const = int(const) % m

        result.append((coeffs, const, m))

    return result


def solve_linear_mod(equations, bounds, verbose=False, **lll_args):
    """Solve an arbitrary system of modular linear equations over different moduli.

    equations: A sequence of (lhs == rhs, M) pairs, where lhs and rhs are expressions and M is the modulus.
    bounds: A dictionary of {var: B} entries, where var is a variable and B is the bounds on that variable.
        Bounds may be specified in one of three ways:
        - A single integer X: Variable is assumed to be uniformly distributed in [0, X] with an expected value of X/2.
        - A tuple of integers (X, Y): Variable is assumed to be uniformly distributed in [X, Y] with an expected value of (X + Y)/2.
        - A tuple of integers (X, E, Y): Variable is assumed to be bounded within [X, Y] with an expected value of E.
        All variables used in the equations must be bounded.
    verbose: set to True to enable additional output
    lll_args: Additional arguments passed to LLL, for advanced usage.

    NOTE: Bounds are *soft*. This function may return solutions above the bounds. If this happens, and the result
    is incorrect, make some bounds tighter and try again.

    Tip: if you get an unwanted solution, try setting the expected values to that solution to force this function
    to produce a different solution.

    Tip: if your bounds are loose and you just want small solutions, set the expected values to zero for all
    loosely-bounded variables.

    >>> k = var('k')
    >>> # solve CRT
    >>> solve_linear_mod([(k == 2, 3), (k == 4, 5), (k == 3, 7)], {k: 3*5*7})
    {k: 59}

    >>> x,y = var('x,y')
    >>> solve_linear_mod([(2*x + 3*y == 7, 11), (3*x + 5*y == 3, 13), (2*x + 5*y == 6, 143)], {x: 143, y: 143})
    {x: 62, y: 5}

    >>> x,y = var('x,y')
    >>> # we can also solve homogenous equations, provided the guesses are zeroed
    >>> solve_linear_mod([(2*x + 5*y == 0, 1337)], {x: 5, y: 5}, guesses={x: 0, y: 0})
    {x: 5, y: -2}
    """

    # The general idea is to set up an integer matrix equation Ax=y by introducing extra variables for the quotients,
    # then use LLL to solve the equation. We introduce extra axes in the lattice to observe the actual solution x,
    # which works so long as the solutions are known to be bounded (which is of course the case for modular equations).
    # Scaling factors are configured to generally push the smallest vectors to have zeros for the relations, and to
    # scale disparate variables to approximately the same base.

    vars = list(bounds)
    guesses = {}
    var_scale = {}
    for var in vars:
        bound = bounds[var]
        if isinstance(bound, Sequence):
            if len(bound) == 2:
                xmin, xmax = map(int, bound)
                guess = (xmax - xmin) // 2 + xmin
            elif len(bound) == 3:
                xmin, guess, xmax = map(int, bound)
            else:
                raise TypeError("Bounds must be integers, 2-tuples or 3-tuples")
        else:
            xmin = 0
            xmax = int(bound)
            guess = xmax // 2
        if not xmin <= guess <= xmax:
            raise ValueError(f"Bound for variable {var} is invalid ({xmin=} {guess=} {xmax=})")
        var_scale[var] = max(xmax - guess, guess - xmin, 1)
        guesses[var] = guess

    var_bits = math.log2(int(prod(var_scale.values()))) + len(vars)
    mod_bits = math.log2(int(prod(m for rel, m in equations)))
    if verbose:
        print(f"verbose: variable entropy: {var_bits:.2f} bits")
        print(f"verbose: modulus entropy: {mod_bits:.2f} bits")

    # Extract coefficients from equations
    equation_coeffs = _process_linear_equations(equations, vars, guesses)

    is_inhom = any(const != 0 for coeffs, const, m in equation_coeffs)

    NR = len(equation_coeffs)
    NV = len(vars)
    if is_inhom:
        # Add one dummy variable for the constant term.
        NV += 1
    B = matrix(ZZ, NR + NV, NR + NV)

    # B format (rows are the basis for the lattice):
    # [ mods:NRxNR 0
    #   eqns:NVxNR vars:NVxNV ]
    # eqns correspond to equation axes, fi(...) = yi mod mi
    # vars correspond to variable axes, which effectively "observe" elements of the solution vector (x in Ax=y)
    # mods and vars are diagonal, so this matrix is lower triangular.

    # Compute maximum scale factor over all variables
    S = max(var_scale.values())

    # Compute equation scale such that the bounded solution vector (equation columns all zero)
    # will be shorter than any vector that has a nonzero equation column
    eqS = S << (NR + NV + 1)
    # If the equation is underconstrained, add additional scaling to find a solution anyway
    if var_bits > mod_bits:
        eqS <<= int((var_bits - mod_bits) / NR) + 1
    col_scales = []

    for ri, (coeffs, const, m) in enumerate(equation_coeffs):
        for vi, c in enumerate(coeffs):
            B[NR + vi, ri] = c
        if is_inhom:
            B[NR + NV - 1, ri] = const
        col_scales.append(eqS)
        B[ri, ri] = m

    # Compute per-variable scale such that the variable axes are scaled roughly equally
    for vi, var in enumerate(vars):
        col_scales.append(S // var_scale[var])
        # Fill in vars block of B
        B[NR + vi, NR + vi] = 1

    if is_inhom:
        # Const block: effectively, this is a bound of 1 on the constant term
        col_scales.append(S)
        B[NR + NV - 1, -1] = 1

    if verbose:
        print("verbose: scaling shifts:", [math.log2(int(s)) for s in col_scales])
        print("verbose: unscaled matrix before:")
        print(B.n())

    for i, s in enumerate(col_scales):
        B[:, i] *= s
    B = B.LLL(**lll_args)
    for i, s in enumerate(col_scales):
        B[:, i] /= s

    # Negate rows for more readable output
    for i in range(B.nrows()):
        if sum(x < 0 for x in B[i, :]) > sum(x > 0 for x in B[i, :]):
            B[i, :] *= -1
        if is_inhom and B[i, -1] < 0:
            B[i, :] *= -1

    if verbose:
        print("verbose: unscaled matrix after:")
        print(B.n())

    for row in B:
        if any(x != 0 for x in row[:NR]):
            # invalid solution: some relations are nonzero
            continue

        if is_inhom:
            # Each row is a potential solution, but some rows may not carry a constant.
            if row[-1] != 1:
                if verbose:
                    print(
                        "verbose: zero solution",
                        {var: row[NR + vi] for vi, var in enumerate(vars) if row[NR + vi] != 0},
                    )
                continue

        res = {}
        for vi, var in enumerate(vars):
            res[var] = row[NR + vi] + guesses[var]

        return res

class MRG:
    def __init__(self,para_len,p, a, b):
        self.init(para_len,p, a, b)

    def next(self):
        self.s = list(self.s[1:]) + [(sum([i * j for (i, j) in zip(self.a, self.s)]) + self.b)]
        return self.s[-1]

    def init(self,para_len,p, a, b):
        F = PolynomialRing(Zmod(p), [f"x_{i}" for i in range(para_len)])
        self.p = p
        self.a = a
        self.b = b
        self.para_len = para_len
        # self.b = randint(1, self.p)
        # self.a = [randint(1, self.p) for i in range(para_len)]
        self.s = list(F.gens())
        self.s_ = list(F.gens())
        # self.s = [var(f"s{i}") for i in range(para_len)]
        # self.s_ = [var(f"s{i}") for i in range(para_len)]

    
    def get_params(self):
        return [self.a,self.b,self.s[0]]
    
    def sol(self, out):
        x = [var(f"x{i}") for i in range(self.para_len)]
        bound = {i: (9, 126) for i in x}
        f = sum(int(i) * j for i, j in zip(self.s[0].coefficients()[:-1], x)) - out + int(self.s[0].coefficients()[-1])
        l = solve_linear_mod([(f == 0, self.p)], bound)
        if l is None or not all( 8 < _ < 127 for _ in l.values()):
            return "1"
        return "0"
Round = 2024
A_len = 10
from tqdm import *
output = [i.strip() for i in open("output.txt", "r").readlines()]
p = int(output[0])
out = eval(output[1])
flag = ""
for a, b, o in tqdm(out):

    temp = MRG(A_len, p, a, b)
    temp.init(A_len, p, a, b)
    for j in range(Round):
        temp.next()
    flag += temp.sol(o)
from Crypto.Util.number import *
print(long_to_bytes(int(flag, 2)))
```

### 5. ez_NTRU
---
**__chall.py__**
```py
from Crypto.Util.number import *
from secret import flag

assert flag.startswith(b"NSSCTF{") and flag.endswith(b"}")
assert b"!!NSSCTF!!" in flag
assert len(flag) == 65

f = bytes_to_long(flag)
p = getPrime(512)
g = getPrime(128)
h = inverse(f,p) * g % p

print('h =', h)
print('p =', p)

#h = 1756927950546402823211991210884487117388985427696056353000574684529449680817044069252055937789026298359737442776894512901268732373696001068086438971265520
#p = 9154925474221530551204374718472364426110749279786123087256403092166680682021327157348820042798042742469289027059354748716972834115194900518063143041804941
```

#### 1. Tổng quan

+ Ta có flag_form như sau : `b"NSSCTF{" + ... + b"!!NSSCTF!!" + ... + b"}"` và độ dài flag là 65
+ $h = f ^ {-1} * g \pmod{p}$ trong đó ta đã biết p, h, `g = getPrime(128)` và với `f` là `flag`

#### 2. Solution

+ Ban đầu mình có thử như sau:
    + $f * h = g \pmod{p}$ nên mình có ma trận $\begin{pmatrix} f & k \end{pmatrix} \begin{pmatrix} 1 & h \\ 0 & p \end{pmatrix} = \begin{pmatrix} f & g \end{pmatrix}$
    do `g` sấp xỉ `128` bit nên mình có nhân vào ma trận thành như sau:
    $\begin{pmatrix} f & k \end{pmatrix} \begin{pmatrix} (2 ^ {128} / 256 ^ {65}) & h \\ 0 & p \end{pmatrix} = \begin{pmatrix} (2 ^ {128}) & g \end{pmatrix}$
    mình thử LLL ma trận trên nhưn không có kết quả nên có lẽ nó bị sai ở đâu đó, khi nhìn lại mình có thấy:

    `f = 'NSSCTF{' * 256^(58) + m_1 * 256 ^ (i + 11) + '!!NSSCTF!!') * 256^(i+1) + m_2 + '}'`
    $flag = prefix + m₁ * 256^{i+11} + suffix + m₂ * 256$ đặt `C = suffix + prefix` ta có ma trận như sau:
    $$
    \begin{pmatrix} m_1 & m_2 & 1 & k \end{pmatrix}
    \begin{pmatrix} 
    256^i & 0 & 0 & 256^{11+i} \times h \times T \\
    0 & 256^{47-i} & 0 & 256h \times T \\
    0 & 0 & 256^{47} & C \times T \\
    0 & 0 & 0 & p \times T
    \end{pmatrix}
    = \begin{pmatrix} m_1 \times 256^i & m_2 \times 256^{47-i} & 256^{47} & g \times T \end{pmatrix}
    $$
    Với T là phần weight = $2 ^ {100}$, còn với i thì ta có thể brute tron khoảng len của `flag`

#### 3. Code

```py
from Crypto.Util.number import *

h = 1756927950546402823211991210884487117388985427696056353000574684529449680817044069252055937789026298359737442776894512901268732373696001068086438971265520
p = 9154925474221530551204374718472364426110749279786123087256403092166680682021327157348820042798042742469289027059354748716972834115194900518063143041804941
l = 65

for i in range(0, 48):

    c = h * (bytes_to_long(b"NSSCTF{")*256^(58) + bytes_to_long(b"}") + bytes_to_long(b"!!NSSCTF!!")*256^(i+1))
    pad = (256 ^ 47) / (2 ^ 128)
    M = matrix([
        [256 ** (47 - i), 0, 0, 256 * h * pad],
        [0, 256 ** (i), 0, (256 ^ (i + 11)) * h * pad],
        [0, 0, 256 ** 47, c * pad],
        [0, 0, 0, p * pad]
    ]).LLL()
    
    try:
        p2 = long_to_bytes(int(abs(M[0, 0]) // 256 ** (47 - i))).decode()
        p1 = long_to_bytes(int(abs(M[0, 1]) // 256 ** (i))).decode()
        print("NSSCTF{" + p1 + "!!NSSCTF!!" + p2 + "}")
    except:
        pass
```

### 6. lcccg

---

**__chall.py__**

```py

import secrets
from Crypto.Util.number import bytes_to_long

flag = b'paluctf{***********}'
class LCG:
    def __init__(self):
        self.x = secrets.randbits(64)
        self.a = 2
        self.m = secrets.randbits(64)

        while self.m % 2 == 0:
            self.m = secrets.randbits(64)

        print("m =", self.m)
    
    def next(self):
        self.x = (self.x * self.a) % self.m
        return self.x

lcg = LCG()

assert b"paluctf" in flag
f = bytes_to_long(flag)

l = f.bit_length()
print("length =", l)

r = 0
for i in range(l + 50):
    r += (lcg.next() & 1) << i

print("cipher =", r ^ f)
# m = 7870528503754256659
# length = 311
# cipher = 3255815260238431584829132773479447408817850185229659648404208268001256903206776002292220185602856730646093869
```

---

#### 1. Tổng quan

+ Đây là một bài `lcg` với `a = 2, b = 0` và m là số nguyên tố đã biết. Ta có bit rất nhiều bit cuối cùng của kết quả được `xor` với flag.

#### 2. Solution
+ Ta có kết quả của hàm `xor` như sau:

    `|---------------------------output--------------------------| ^ |---50 bit 0--------------------------flag-----------------|`

    -> `|output(50bit)|-------------output ^ flag-----------------|` = `|output(50bit)|output ^ "paluctf{"|---output ^ flag---|`

    -> Từ đó ta có thể tìm lại được nhiều đầu ra của `lcg`
+ do tham số của khóa đặc biệt nên ta có:
    x1 = 2 * x0 % m, x2 = 2 * x1 = 4 * x0 % m

+ Thông thường nếu bạn nhân đôi số sẽ nhận được số chẵn, nhưng vì đã bị chia dư cho m (là số nguyên tố lẻ) nên không nhất thiết phải nhận được số chẵn. Vậy khi 2 * x mà < m thì ta dễ thấy đây là số chẵn và kết quả sẽ cho ta bit `0`, khi 2 * x >= m đây là thời điểm kết quả của ta là `1`. Mình hướng tới tìm kiếm nhị phân để tìm lại kết quả. 
    + Không gian tìm kiếm ban đầu: 2⁶⁴
    + Sau mỗi bit: chia đôi không gian tìm kiếm
Từ đó, bằng cách biết bit 1 của x1 là 0 hay 1, hai lần LCG sẽ trở thành

    + x2 = 2 * x1 = 4 * x0 %m

Hãy suy nghĩ theo cách tương tự, khi muốn biết giá trị của x0

    + Khi giá trị của x1 là số chẵn thì đó là nửa bên trái và khi là số lẻ thì đó là nửa bên phải.
    + Nếu giá trị của x2 là số chẵn thì đó là nửa bên trái và khi là số lẻ thì đó là nửa bên phải.
    + Nếu giá trị của x3 là số chẵn thì đó là nửa bên trái và khi là số lẻ thì đó là nửa bên phải.

+ ngoài ra ta còn thể thấy:
    + `x1 = 2 * x0 % m = 2 * x0 + k * m` nên `x2 = 2 * x1 = 4 * x0 + 2 * k * m` ta cũng có thể tìm lại được số k sau mỗi lần chạy.
Tổng hợp các điều kiện trên mình viết code chạy tìm kiếm nhị phân. Từ đó ta có thể tìm lại được kết quả của hàm `lcg` và ta chỉ cần nhân lại một bôị số nghịch đảo của a là ta có thể có được `seed` từ đó tìm lại hết output và lấy được flag.

#### 3. Code

```py

from Crypto.Util.number import *

class LCG:
    def __init__(self, x, m):
        self.x = x
        self.a = 2
        self.m = m

    def next(self):
        self.x = (self.x * self.a) % self.m
        return self.x

m = 7870528503754256659
length = 311
cipher = 3255815260238431584829132773479447408817850185229659648404208268001256903206776002292220185602856730646093869
a = 2

form = b'paluctf{'
l = bytes_to_long(form).bit_length()

out = int(bin(cipher)[2:][:l + 50], 2) ^ bytes_to_long(form)

o = []

for i in range(out.bit_length()):
    o.append((out >> i) & 1)

l, r = 0, m

for i in o:
    
    mid = (r + l) >> 1
    
    if i:
        l = mid
    else:
        r = mid

for i in range(10):
    
    seed = l + i
    
    for i in range(361 - len(o)):
        seed = seed * inverse(2,m) % m
        
    lcg = LCG(seed, m)

    r = 0
    for i in range(length + 50):
        r += (lcg.next() & 1) << i

    print(long_to_bytes(r ^ cipher))

```

### 7. Leak_RSA

---
**__chall.py__**


```py
from Crypto.Util.number import *
flag = b'paluctf{******************}'
p = getPrime(512)
q = getPrime(512)
m = bytes_to_long(flag)
n = p * q
e = 0x10001
c = pow(m, e, n)
leak1 = p & q
leak2 = p | q
print(n)
print(leak1)
print(leak2)
print(c)
# 116117067844956812459549519789301338092862193317140117457423221066709482979351921356314593636327834899992321545232613626111009441254302384449742843180876494341637589103640217194070886174972452908589438599697165869525189266606983974250478298162924187424655566019487631330678770727392051485223152309309085945253
# 8605081049583982438298440507920076587069196185463800658188799677857096281403951362058424551032224336538547998962815392172493849395335237855201439663804417
# 13407373154151815187508645556332614349998109820361387104317659096666170318961881115942116046384020162789239054091769561534320831478500568385569270082820389
# 77391898018025866504652357285886871686506090492775075964856060726697268476460193878086905273672532025686191143120456958000415501059102146339274402932542049355257662649758904431953601814453558068056853653214769669690930883469679763807974430229116956128100328073573783801082618261383412539474900566590518020658
```
---

#### 1. Tổng quan

+ Một bài đơn giản với mã hóa RSA trong đó `q, p = getPrime(512)` và ta có phần leak là `p | q` và `p & q`.

#### 2. Solution

+ Mình thực hiện viết code brute từng bít sao cho thỏa mãn các điều kiện sau:
    + $(p_ × 2^i + k_1) × (q_ × 2^i + k_2) = p_ × q_ × 2^{2i} + k_2 × p_ × 2^i + k_1 × q_ × 2^i + k_1 × k_2$
    -> $k_1 × k_2 \equiv n \pmod{2^i}$ tức với i bit cuối của q, p thì tích của nó phải bằng i bit cuối của n.
    + Sử dụng thêm các điều kiện `and` và `or` bit để giảm các trường hợp có thể.

#### 3. Code

```py

from Crypto.Util.number import *
n = 116117067844956812459549519789301338092862193317140117457423221066709482979351921356314593636327834899992321545232613626111009441254302384449742843180876494341637589103640217194070886174972452908589438599697165869525189266606983974250478298162924187424655566019487631330678770727392051485223152309309085945253
hint_and = 8605081049583982438298440507920076587069196185463800658188799677857096281403951362058424551032224336538547998962815392172493849395335237855201439663804417
hint_or = 13407373154151815187508645556332614349998109820361387104317659096666170318961881115942116046384020162789239054091769561534320831478500568385569270082820389
c = 77391898018025866504652357285886871686506090492775075964856060726697268476460193878086905273672532025686191143120456958000415501059102146339274402932542049355257662649758904431953601814453558068056853653214769669690930883469679763807974430229116956128100328073573783801082618261383412539474900566590518020658

def find(p, q):
    
    p_, _q = int(p, 2), int(q, 2)
    
    if len(p) == 512 and isPrime(p_) and isPrime(_q):
        print(p_, _q)
    
    else:
        MOD = 2 ** (len(q))
        if (p_ * _q) % MOD == n % MOD and (p_ | _q) % (MOD) == hint_or % (MOD) and (p_ & _q) % (MOD) == hint_and % (MOD):
            
            find("1" + p, "1" + q)
            find("0" + p, "1" + q)
            find("1" + p, "0" + q)
            find("0" + p, "0" + q)

find("1", "1")
p, q = 13246755426378578729876630630718068462717569987788401039611945190239825377062020349346567434694413153125153375769817998716719780574738862166452227093778437, 8765698777357218895930455433534622474349736018036786722894513584283441223303812128653973162721831346202633677284766954990094900299096944074318482652846369

print(long_to_bytes(pow(c, pow(65537, -1, (p - 1) * (q - 1)), n)))
```

### 8. ez_copper_1

---

**__chall.py__**

```py
from Crypto.Util.number import *
from random import *
from secret import flag

assert flag.startswith(b"NSSCTF{") and flag.endswith(b"}")
assert len(flag) == 37

def gen_data(p,length):
    coeff = [randint(-2**32,2**32) for i in range(length-1)] + [randint(1,2**32)]
    return sum([coeff[i]*p**i for i in range(length)])

b = getPrime(1400)
a = gen_data(b,6)
p = getPrime(256*5)
q = getPrime(256)
n = p
m = bytes_to_long(flag[7:-1])

print("a =",a)
print("b =",b)
print("n =",n)
print("c =",a % (b-m) % p)

'''
a = 29089145861698849533587576973295257566874181013683093409280511461881508560043226639624028591697075777027609041083214241167067154846780379410457325384136774173540880680703437648293957784878985818376432013647415210955529162712672841319668120257447461567038004250028029752246949587461150846214998661348798142220559280403267581983191669260262076357617420472179861844334505141503479938585740507007167412328247901645653025038188426412803561167311075415186139406418297360055617953651023218144335111178729068397052382593835592142212067930715544738880011596139654527770961911784544010189290315677772431190278256579916333137165255075163459126978209678330136547554839703581615386678643718339211024128344190549574517564644382447611744798875041346881354781693931986615205673317996958906543168487424513288646586386898335386252942417294351991435595389041536593887748040184886941013614961741810729168951559211294246606230105751075721451317188926451002620849423314518170658209171671914315184519999959495351937563075042077266900864146159426562183965523296477064353921084645981585062809887031916148806349242025315612913825933164149679421566262446757892475611986630543538188150542432463200651189833933982458007114429715435568714619661080138790893459960671301328455259702189597680258358027148120577359065875450633562059381985788036798654456426180261922908112060328808638698523351620789566317389045953829508142189900185007810978556531031234520426854056485675147172190502028351264431318960694075186507102430581156550179324060430995652420952731818727684039692796018771140481392835706804763480391403219506727895338895364591606497253163676677638669786786858737497920439433198267927890300667623673919500396414839378381934354516285899285278671196050670328000271445003863863854641343057226519772851093922041622949244909881042639419520750870739146022239848882362576253955639971615811326995401478442990402656532205515168792715334542129193521733882886780427236290633270965571593377055933030570964314193668632743086843644521712276882644432083012275643889490106050284317873072564495246844741833922331897169054478543498374111011001360629887265387016903
b = 23842135454777432891743223391138265563241799870175456642327123278749657522050965688647025271946838603033997215457359121062031090678062337376719430593135764515364544052891212988546634081941717578522276652565205405071925932782899189391582928430745625545751168223235578140422316604775465116636679365817463642606682382103650151553859378443311951637645862682606805670610169631771916714125895199501221576523042203542953632992797
n = 11325979084644128572298911896847368512066889699114922766957825496829789701040409280284912163337390977205935027654824418075908113980923567819511384456223871894254826496727684822147076089401320253972280078822901143659851738555573580052473815798989309369428595758953805619194262607259107358103749807085316873971927412767250429330952340169403993890298557816024130952523480708504075717017477
c = 91637278981727419311704062766528605893241365739887714388981571071807672497690225964001055671982318124750997320763003521883860470498708606433206468782382765369836856610266602374015551078759628514665188339252922366320922478645026704734702460355236791287112842409076450962765866362852307351865564192898522584768904066046337899302561685937649000409332117647123
'''
```

#### 1. Tổng quan

+ Ta đã biết các thông số `a, b, n, c` trong đó:
    + `b` là số prime 1024 bit
    + `a` là kết quả của hàm `gen_data`, hàm đó như sau:
    
    $a = \sum_{i = 0}^{6}{{c_i} * b ^ {i}}$ trong đó `c_i` là các số ngẫu nhiên nhỏ.

    + `n = p` mặc dù đáng ra n = p * q nhưng có vẻ đây là lỗi của người ra đề ?

    + `c` là kết quả của phép tính $a \% (b - m) \% n$

#### 2. Solution

+ viết lại phép tính trên thì ta có như sau:

$a \% (b - m) \% n = \sum_{i = 0}^{6}{{c_i} * b ^ {i}} \% (b - m) \% n$

mà trong python các phép tính được thực hiện từ trái qua phải nên phép mod (b - m) sẽ được thực hiện trước mà trong trường (b - m) có đặc điểm như sau:

+ $b - m = 0 \pmod{b - m} \to b = m \pmod{b - m}$

$\sum_{i = 0}^{6}{{c_i} * b ^ {i}} = \sum_{i = 0}^{6}{{c_i} * m ^ {i}} \% (b - m) \% n$

+ ngoài ra ta còn thấy, flag có 37 ký tự mà đã bị bỏ đi tám ký tự nên chỉ còn 29 ký tự tức số a ở đây chỉ có lớn hơn $2 ^ {32} * 256 ^ {29}$ một chút và số này nhỏ hơn trường (b - m) lẫn trường (p) nền ta có thể viết

$c = \sum_{i = 0}^{6}{{c_i} * m ^ {i}}$

+ Bây giờ việt của ta cần là tìm lại các hệ số `c_i` nhưng điều này khá dễ vì nó khá nhỏ nên mình dùng hàm solve_linear_mod để giải. Sau khi có được các hệ số chỉ cần dùng hàm roots là ta sẽ có flag.

#### 3. Code

```py
from Crypto.Util.number import *
from random import *
import string

import itertools

from collections.abc import Sequence
import math
import operator
from typing import List, Tuple
from sage.all import ZZ, gcd, matrix, prod, var


def _process_linear_equations(equations, vars, guesses) -> List[Tuple[List[int], int, int]]:
    result = []

    for rel, m in equations:
        op = rel.operator()
        if op is not operator.eq:
            raise TypeError(f"relation {rel}: not an equality relation")

        expr = (rel - rel.rhs()).lhs().expand()
        for var in expr.variables():
            if var not in vars:
                raise ValueError(f"relation {rel}: variable {var} is not bounded")

        # Fill in eqns block of B
        coeffs = []
        for var in vars:
            if expr.degree(var) >= 2:
                raise ValueError(f"relation {rel}: equation is not linear in {var}")
            coeff = expr.coefficient(var)
            if not coeff.is_constant():
                raise ValueError(f"relation {rel}: coefficient of {var} is not constant (equation is not linear)")
            if not coeff.is_integer():
                raise ValueError(f"relation {rel}: coefficient of {var} is not an integer")

            coeffs.append(int(coeff) % m)

        # Shift variables towards their guesses to reduce the (expected) length of the solution vector
        const = expr.subs({var: guesses[var] for var in vars})
        if not const.is_constant():
            raise ValueError(f"relation {rel}: failed to extract constant")
        if not const.is_integer():
            raise ValueError(f"relation {rel}: constant is not integer")

        const = int(const) % m

        result.append((coeffs, const, m))

    return result


def solve_linear_mod(equations, bounds, verbose=False, **lll_args):
    """Solve an arbitrary system of modular linear equations over different moduli.

    equations: A sequence of (lhs == rhs, M) pairs, where lhs and rhs are expressions and M is the modulus.
    bounds: A dictionary of {var: B} entries, where var is a variable and B is the bounds on that variable.
        Bounds may be specified in one of three ways:
        - A single integer X: Variable is assumed to be uniformly distributed in [0, X] with an expected value of X/2.
        - A tuple of integers (X, Y): Variable is assumed to be uniformly distributed in [X, Y] with an expected value of (X + Y)/2.
        - A tuple of integers (X, E, Y): Variable is assumed to be bounded within [X, Y] with an expected value of E.
        All variables used in the equations must be bounded.
    verbose: set to True to enable additional output
    lll_args: Additional arguments passed to LLL, for advanced usage.

    NOTE: Bounds are *soft*. This function may return solutions above the bounds. If this happens, and the result
    is incorrect, make some bounds tighter and try again.

    Tip: if you get an unwanted solution, try setting the expected values to that solution to force this function
    to produce a different solution.

    Tip: if your bounds are loose and you just want small solutions, set the expected values to zero for all
    loosely-bounded variables.

    >>> k = var('k')
    >>> # solve CRT
    >>> solve_linear_mod([(k == 2, 3), (k == 4, 5), (k == 3, 7)], {k: 3*5*7})
    {k: 59}

    >>> x,y = var('x,y')
    >>> solve_linear_mod([(2*x + 3*y == 7, 11), (3*x + 5*y == 3, 13), (2*x + 5*y == 6, 143)], {x: 143, y: 143})
    {x: 62, y: 5}

    >>> x,y = var('x,y')
    >>> # we can also solve homogenous equations, provided the guesses are zeroed
    >>> solve_linear_mod([(2*x + 5*y == 0, 1337)], {x: 5, y: 5}, guesses={x: 0, y: 0})
    {x: 5, y: -2}
    """

    # The general idea is to set up an integer matrix equation Ax=y by introducing extra variables for the quotients,
    # then use LLL to solve the equation. We introduce extra axes in the lattice to observe the actual solution x,
    # which works so long as the solutions are known to be bounded (which is of course the case for modular equations).
    # Scaling factors are configured to generally push the smallest vectors to have zeros for the relations, and to
    # scale disparate variables to approximately the same base.

    vars = list(bounds)
    guesses = {}
    var_scale = {}
    for var in vars:
        bound = bounds[var]
        if isinstance(bound, Sequence):
            if len(bound) == 2:
                xmin, xmax = map(int, bound)
                guess = (xmax - xmin) // 2 + xmin
            elif len(bound) == 3:
                xmin, guess, xmax = map(int, bound)
            else:
                raise TypeError("Bounds must be integers, 2-tuples or 3-tuples")
        else:
            xmin = 0
            xmax = int(bound)
            guess = xmax // 2
        if not xmin <= guess <= xmax:
            raise ValueError(f"Bound for variable {var} is invalid ({xmin=} {guess=} {xmax=})")
        var_scale[var] = max(xmax - guess, guess - xmin, 1)
        guesses[var] = guess

    var_bits = math.log2(int(prod(var_scale.values()))) + len(vars)
    mod_bits = math.log2(int(prod(m for rel, m in equations)))
    if verbose:
        print(f"verbose: variable entropy: {var_bits:.2f} bits")
        print(f"verbose: modulus entropy: {mod_bits:.2f} bits")

    # Extract coefficients from equations
    equation_coeffs = _process_linear_equations(equations, vars, guesses)

    is_inhom = any(const != 0 for coeffs, const, m in equation_coeffs)

    NR = len(equation_coeffs)
    NV = len(vars)
    if is_inhom:
        # Add one dummy variable for the constant term.
        NV += 1
    B = matrix(ZZ, NR + NV, NR + NV)

    # B format (rows are the basis for the lattice):
    # [ mods:NRxNR 0
    #   eqns:NVxNR vars:NVxNV ]
    # eqns correspond to equation axes, fi(...) = yi mod mi
    # vars correspond to variable axes, which effectively "observe" elements of the solution vector (x in Ax=y)
    # mods and vars are diagonal, so this matrix is lower triangular.

    # Compute maximum scale factor over all variables
    S = max(var_scale.values())

    # Compute equation scale such that the bounded solution vector (equation columns all zero)
    # will be shorter than any vector that has a nonzero equation column
    eqS = S << (NR + NV + 1)
    # If the equation is underconstrained, add additional scaling to find a solution anyway
    if var_bits > mod_bits:
        eqS <<= int((var_bits - mod_bits) / NR) + 1
    col_scales = []

    for ri, (coeffs, const, m) in enumerate(equation_coeffs):
        for vi, c in enumerate(coeffs):
            B[NR + vi, ri] = c
        if is_inhom:
            B[NR + NV - 1, ri] = const
        col_scales.append(eqS)
        B[ri, ri] = m

    # Compute per-variable scale such that the variable axes are scaled roughly equally
    for vi, var in enumerate(vars):
        col_scales.append(S // var_scale[var])
        # Fill in vars block of B
        B[NR + vi, NR + vi] = 1

    if is_inhom:
        # Const block: effectively, this is a bound of 1 on the constant term
        col_scales.append(S)
        B[NR + NV - 1, -1] = 1

    if verbose:
        print("verbose: scaling shifts:", [math.log2(int(s)) for s in col_scales])
        print("verbose: unscaled matrix before:")
        print(B.n())

    for i, s in enumerate(col_scales):
        B[:, i] *= s
    B = B.LLL(**lll_args)
    for i, s in enumerate(col_scales):
        B[:, i] /= s

    # Negate rows for more readable output
    for i in range(B.nrows()):
        if sum(x < 0 for x in B[i, :]) > sum(x > 0 for x in B[i, :]):
            B[i, :] *= -1
        if is_inhom and B[i, -1] < 0:
            B[i, :] *= -1

    if verbose:
        print("verbose: unscaled matrix after:")
        print(B.n())

    for row in B:
        if any(x != 0 for x in row[:NR]):
            # invalid solution: some relations are nonzero
            continue

        if is_inhom:
            # Each row is a potential solution, but some rows may not carry a constant.
            if row[-1] != 1:
                if verbose:
                    print(
                        "verbose: zero solution",
                        {var: row[NR + vi] for vi, var in enumerate(vars) if row[NR + vi] != 0},
                    )
                continue

        res = {}
        for vi, var in enumerate(vars):
            res[var] = row[NR + vi] + guesses[var]

        return res
a = 29089145861698849533587576973295257566874181013683093409280511461881508560043226639624028591697075777027609041083214241167067154846780379410457325384136774173540880680703437648293957784878985818376432013647415210955529162712672841319668120257447461567038004250028029752246949587461150846214998661348798142220559280403267581983191669260262076357617420472179861844334505141503479938585740507007167412328247901645653025038188426412803561167311075415186139406418297360055617953651023218144335111178729068397052382593835592142212067930715544738880011596139654527770961911784544010189290315677772431190278256579916333137165255075163459126978209678330136547554839703581615386678643718339211024128344190549574517564644382447611744798875041346881354781693931986615205673317996958906543168487424513288646586386898335386252942417294351991435595389041536593887748040184886941013614961741810729168951559211294246606230105751075721451317188926451002620849423314518170658209171671914315184519999959495351937563075042077266900864146159426562183965523296477064353921084645981585062809887031916148806349242025315612913825933164149679421566262446757892475611986630543538188150542432463200651189833933982458007114429715435568714619661080138790893459960671301328455259702189597680258358027148120577359065875450633562059381985788036798654456426180261922908112060328808638698523351620789566317389045953829508142189900185007810978556531031234520426854056485675147172190502028351264431318960694075186507102430581156550179324060430995652420952731818727684039692796018771140481392835706804763480391403219506727895338895364591606497253163676677638669786786858737497920439433198267927890300667623673919500396414839378381934354516285899285278671196050670328000271445003863863854641343057226519772851093922041622949244909881042639419520750870739146022239848882362576253955639971615811326995401478442990402656532205515168792715334542129193521733882886780427236290633270965571593377055933030570964314193668632743086843644521712276882644432083012275643889490106050284317873072564495246844741833922331897169054478543498374111011001360629887265387016903
b = 23842135454777432891743223391138265563241799870175456642327123278749657522050965688647025271946838603033997215457359121062031090678062337376719430593135764515364544052891212988546634081941717578522276652565205405071925932782899189391582928430745625545751168223235578140422316604775465116636679365817463642606682382103650151553859378443311951637645862682606805670610169631771916714125895199501221576523042203542953632992797
n = 11325979084644128572298911896847368512066889699114922766957825496829789701040409280284912163337390977205935027654824418075908113980923567819511384456223871894254826496727684822147076089401320253972280078822901143659851738555573580052473815798989309369428595758953805619194262607259107358103749807085316873971927412767250429330952340169403993890298557816024130952523480708504075717017477
c = 91637278981727419311704062766528605893241365739887714388981571071807672497690225964001055671982318124750997320763003521883860470498708606433206468782382765369836856610266602374015551078759628514665188339252922366320922478645026704734702460355236791287112842409076450962765866362852307351865564192898522584768904066046337899302561685937649000409332117647123
coeff = [var(f"x_{i}") for i in range(6)]

def gen_data(coeff, p,length):
    
    return sum([coeff[i]*p**i for i in range(length)])

f = gen_data(coeff, b, 6) - a
b = {i: (-2**32,2**32) for i in coeff}
coeff = [_ for _ in solve_linear_mod([[f == 0, n]], b).values()]

F.<x> = PolynomialRing(GF(n))
f = gen_data(coeff, x, 6) - c
print(long_to_bytes(int(f.roots()[0][0])))
```

### 9. ez_factor_1

---

**__chall.py__**

```py
from Crypto.Util.number import *
from Crypto.Util.Padding import *
from Crypto.Cipher import AES
from hashlib import sha256
from random import *
from secret import flag

p,q,r = getPrime(256),getPrime(256),getPrime(256)
n = p*q*r
phi = (p-1)*(q-1)*(r-1)

key = sha256(str(p+q+r).encode()).digest()
enc = AES.new(key, AES.MODE_ECB)
c = enc.encrypt(pad(flag,16))

print("n =",n)
print("hint =",getrandbits(256)*phi**3)
print("c =",c)

'''
n = 343127312894441264623060100705188723106648253383902349620699412384677995734576572885137280031507308915752070128528949423639735964709160841591038148069185325450544546735392923674211031016035209702254447128968565740534765322198664691
hint = 3802744632475774666777934738986183209966233570124815804333822490240409933768208822899072601181527365734196352249978937639454658680559993507805820991037544059215540360338084909833242583087617315128513337647913472696515770688338805196215328080662137260951972365100322795737835152857750114216709340410268143017180826135339564387228460663261697814425298725805568817218360964967025967384766127098203664964210047103829182895016532403825215903779806760754721373523135367007867453212189953817229696304611549977864533229540971457717668560698088917340909962348110683581294453903261530189579223087858081200349343639420534779115290433982968345085704202494045885911950427043282588446343291558819683037970053828479057449781943479407877748772895179095205885377333120540311815022381056
c = b';#\x1b\xa6R\xe2\x1d\x9dpf\x8e\xda\xe4\x14\x9a\xfb\tr\x99\x8a\xc9r\x03C\xb58Zb\x97\x0b\xc7S\x0fa\x88\xb4\xe4\x16.M\x92\x94\x94\x8b\xa9Ki\x9b\xe4\xe9d5\xa3~\x1a\x9cx\x03\xdc\x1f\x87\x14E\x90'
'''
```

#### 1. Tổng quan

+ Với `n = p * q * r` ta đã biết `n` và `k * phi ^ 3` và muc tiêu của ta là tìm lại `p, q, r`

#### 2. Solution

+ Và khi cố gắng phân tích `k * phi^3`, có thể nhận được danh sách các thừa số sau:

`2^11 · 3^6 · 7^3 · 13^6 · 41^3 · 79^3 · 83^3 · 277^3 · 248701^3 · 2421845446...11<714>`

Ta có thể thấy có các hệ số được mũ 3 lần điều đó cho thấy số đó có thể là ước của một trong bộ 3 số (p - 1), (q - 1), (r - 1). Vì thứ tự không quan trọng nên ta giải sử 7 là ước số của (p - 1). Thì ta có:

+ $t = k * {phi} ^ 3 / 7 ^ 3$ khi đó với một số nguyên bất kỳ( ở đay mình chọn là 2 cho đơn giản) ta có:
+ $2 ^ t = 1 \pmod{q * r}$
+ $2 ^ t \neq 1 \pmod{n}$

nên :
+ $2 ^ t - 1 = k_1 * q * r \to 2 ^ t - 1 = k_3 * q * r \mod{n}$

$\to gcd(2 ^ t - 1, n) = q * r$

Cứ tiếp tục như vậy đến khi tìm lại được hết các số nguyên tố là ta dễ dàng có flag.

#### 3. Code

```py

from Crypto.Util.number import *
from Crypto.Util.Padding import *
from Crypto.Cipher import AES
from hashlib import sha256
from itertools import combinations

n = 343127312894441264623060100705188723106648253383902349620699412384677995734576572885137280031507308915752070128528949423639735964709160841591038148069185325450544546735392923674211031016035209702254447128968565740534765322198664691
hint = 3802744632475774666777934738986183209966233570124815804333822490240409933768208822899072601181527365734196352249978937639454658680559993507805820991037544059215540360338084909833242583087617315128513337647913472696515770688338805196215328080662137260951972365100322795737835152857750114216709340410268143017180826135339564387228460663261697814425298725805568817218360964967025967384766127098203664964210047103829182895016532403825215903779806760754721373523135367007867453212189953817229696304611549977864533229540971457717668560698088917340909962348110683581294453903261530189579223087858081200349343639420534779115290433982968345085704202494045885911950427043282588446343291558819683037970053828479057449781943479407877748772895179095205885377333120540311815022381056
c = b';#\x1b\xa6R\xe2\x1d\x9dpf\x8e\xda\xe4\x14\x9a\xfb\tr\x99\x8a\xc9r\x03C\xb58Zb\x97\x0b\xc7S\x0fa\x88\xb4\xe4\x16.M\x92\x94\x94\x8b\xa9Ki\x9b\xe4\xe9d5\xa3~\x1a\x9cx\x03\xdc\x1f\x87\x14E\x90'

k = factor(int(hint), limit = 2 ** 20)[:-1]
lst = []
for i, j in k:
    for _ in range(0, j - 2):
        lst.append(i ** j)

tmp = list(set([gcd(n, pow(2, hint // _, n) - 1) for _ in lst]))
tmp = [gcd(i, j) for i, j in combinations(tmp, 2)]

p, q, r = tmp
key = sha256(str(p+q+r).encode()).digest()
enc = AES.new(key, AES.MODE_ECB)
print(enc.decrypt(c))
```

### 10. ez_factor_2

---

**__chall.py__**

```py
from Crypto.Util.number import *
from random import *
from gmpy2 import *
from secret import flag

m = bytes_to_long(flag)

def gen_prime(bits,common_bits):
    shift = bits - common_bits
    while(True):
        high = ((1<<(common_bits-1)) + getrandbits(common_bits-1)) << shift
        p = high + 2*getrandbits(shift-1) + 1
        q = high + 2*getrandbits(shift-1) + 1
        if(isPrime(p) and isPrime(q)):
            return p,q

p,q = gen_prime(1024,350)
n = p*q
leak = (pow(p,q,n) + pow(q,p,n)) & ((1 << 300) - 1)
e = 65537
c = pow(m,e,n)

print("n =",n)
print("e =",e)
print("c =",c)
print("leak =",leak)

#n = 20304817598463991883487911425007927214135740826150882692657608404060781116387976327509281041677948119173928648751205240686682904704601086882134602075008186227364732648337539221512524800875230120183740426722086488143679856177002068856911689386346260227545638754513723197073169314634515297819111746527980650406024533140966706487847121511407833611739619493873042466218612052791074001203074880497201822723381092411392045694262494838335876154820241827541930328508349759776586915947972105562652406402019214248895741297737940426853122270339018032192731304168659857343755119716209856895953244774989436447915329774815874911183
#e = 65537
#c = 7556587235137470264699910626838724733676624636871243497222431220151475350453511634500082904961419456561498962154902587302652809217390286599510524553544201322937261018961984214725167130840149912862814078259778952625651511254849935498769610746555495241583284505893054142602024818465021302307166854509140774804110453227813731851908572434719069923423995744812007854861031927076844340649660295411912697822452943265295532645300241560020169927024244415625968273457674736848596595931178772842744480816567695738191767924194206059251669256578685972003083109038051149451286043920980235629781296629849866837148736553469654985208
#leak = 1511538174156308717222440773296069138085147882345360632192251847987135518872444058511319064
```

#### 1. Tổng quan

+ có `p, q` là kết quả của hàm `gen_prime`, khi nhìn vào hàm ta thấy:
```py
def gen_prime(bits,common_bits):
    shift = bits - common_bits
    while(True):
        high = ((1<<(common_bits-1)) + getrandbits(common_bits-1)) << shift
        p = high + 2*getrandbits(shift-1) + 1
        q = high + 2*getrandbits(shift-1) + 1
        if(isPrime(p) and isPrime(q)):
            return p,q
```
p, q đều có 350 bit đầu giống nhau.
+ flag được mã hóa bằng `n = p * q` và ta có leak là $p ^ q + q ^ p \pmod(n)$

#### 2. Solution

+ Ta có $l = p ^ q + q ^ p \pmod{n}$ mà

$l = p \pmod{q}$

$l = q \pmod{p}$

Khi sử dụng định lý phần dư trung hoa ta sẽ thấy $l = p + q \mod{n}$ mà $p + q < n$ nên l thật ra là 300 bit cuối của $p + q$

+ mà ta có thể dễ dàng tìm lại được 350 bít đầu của p, q bằng căn bậc 2. Do p, q rất gần nhau nên ta sử dụng fermat attack để tìm lại p, q

#### 3. Code

```py

from Crypto.Util.number import *
from random import *
from gmpy2 import *
from tqdm import *
n = 20304817598463991883487911425007927214135740826150882692657608404060781116387976327509281041677948119173928648751205240686682904704601086882134602075008186227364732648337539221512524800875230120183740426722086488143679856177002068856911689386346260227545638754513723197073169314634515297819111746527980650406024533140966706487847121511407833611739619493873042466218612052791074001203074880497201822723381092411392045694262494838335876154820241827541930328508349759776586915947972105562652406402019214248895741297737940426853122270339018032192731304168659857343755119716209856895953244774989436447915329774815874911183
e = 65537
c = 7556587235137470264699910626838724733676624636871243497222431220151475350453511634500082904961419456561498962154902587302652809217390286599510524553544201322937261018961984214725167130840149912862814078259778952625651511254849935498769610746555495241583284505893054142602024818465021302307166854509140774804110453227813731851908572434719069923423995744812007854861031927076844340649660295411912697822452943265295532645300241560020169927024244415625968273457674736848596595931178772842744480816567695738191767924194206059251669256578685972003083109038051149451286043920980235629781296629849866837148736553469654985208
leak = 1511538174156308717222440773296069138085147882345360632192251847987135518872444058511319064
l =(( 2 * iroot(n, 2)[0] >> 325) << 325)

for i in trange(1 << 25, 1 << 24, -1):
    a = l + i * (1 << 300) + leak
    if (a ** 2 > 4 * n):
        tmp = iroot(a ** 2 - 4 * n, 2)
        if tmp[1]:
            p = (a + tmp[0]) // 2
            q = (a - tmp[0]) // 2
            print(p, q)
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            print(long_to_bytes(m))
            break
```

### 11. ez_factor_3

---
**__chall.py__**

```py
from Crypto.Util.number import *
from secret import flag

def gen_noisy_sum_of_base(m,p):
    sum = 0
    while(m):
        sum += m % p
        m //= p
    return sum//1000

m = bytes_to_long(flag)
e = 65537
p = getPrime(256)
q = getPrime(256)
n = p*q

m1 = getRandomNBitInteger(2048)
m2 = getRandomNBitInteger(2048)
print("m1 =",m1)
print("m2 =",m2)
print("sum1 =",gen_noisy_sum_of_base(m1,p))
print("sum2 =",gen_noisy_sum_of_base(m2,p))
print("n =",n)
print("c =",pow(m,e,n))

'''
m1 = 23145761572719481962762273155673006162798724771853359777738044204075205506442533110957905454673168677138390288946164925146182350082798412822843805544411533748092944111577005586562560198883223125408349637392132331590745338744632420471550117436081738053152425051777196723492578868061454261995047266710226954140246577840642938899700421187651113304598644654895965391847939886431779910020514811403672972939220544348355199254228516702386597854501038639792622830084538278039854948584633614251281566284373340450838609257716124253976669362880920166668588411500606044047589369585384869618488029661584962261850614005626269748136
m2 = 21293043264185301689671141081477381397341096454508291834869907694578437286574195450398858995081655892976217341587431170279280993193619462282509529429783481444479483042173879669051228851679105028954444823160427758701176787431760859579559910604299900563680491964215291720468360933456681005593307187729279478018539532102837247060040450789168837047742882484655150731188613373706854145363872001885815654186972492841075619196485090216542847074922791386068648687399184582403554320117303153178588095463812872354300214532980928150374681897550358290689615020883772588218387143725124660254095748926982159934321361143271090861833
sum1 = 309575642078438773208947649750793560438038690144069550000470706236111082406
sum2 = 303394719183577651416751448350927044928060280972644968966068528268042222965
n = 4597063839057338886607228486569583368669829061896475991448013970518668754752831268343529061846220181652766402988715484221563478749446497476462877699249731
c = 3253873276452081483545152055347615580632252871708666807881332670645532929747667442194685757039215506084199053032613562932819745309368748317106660561209205
'''
```
---

#### 1. Tổng quan

+ Với `p = getPrime(256), q = getPrime(256)`, flag vẫn được mã hóa như bình thường nhưng lần này leak của ta lại là tổng các hệ số của `m1, m2` trong hệ cơ số `p`.

#### 2. solution

+ Có thể viết lại như sau:

$m1 = x_0 + x_1 * p + x_2 * {p ^ 2} + ...$
$sum_1 = x_0 + x_1 +x_2 + ...$

$\to m1 - sum_1 = x_1 * p - x_1 + x_2 * {p ^ 2} - x_2 + ...$
$m1 - sum_1 = x_1 * (p - 1) + x_2 * ({p ^ 2} - 1) + ... + ? * ({p^ n} - 1) = k_1 * (p - 1)$
$m2 - sum_2 = k_2 * (p - 1)$

TỪ đó `p - 1 = gcd(m2 - sum_2, m1 - sum_1)`
và ta dễ dàng có thể tìm lại flag.

#### 3. Code

```py

from Crypto.Util.number import *
from tqdm import *
from gmpy2 import *

e = 65537

m1 = 23145761572719481962762273155673006162798724771853359777738044204075205506442533110957905454673168677138390288946164925146182350082798412822843805544411533748092944111577005586562560198883223125408349637392132331590745338744632420471550117436081738053152425051777196723492578868061454261995047266710226954140246577840642938899700421187651113304598644654895965391847939886431779910020514811403672972939220544348355199254228516702386597854501038639792622830084538278039854948584633614251281566284373340450838609257716124253976669362880920166668588411500606044047589369585384869618488029661584962261850614005626269748136
m2 = 21293043264185301689671141081477381397341096454508291834869907694578437286574195450398858995081655892976217341587431170279280993193619462282509529429783481444479483042173879669051228851679105028954444823160427758701176787431760859579559910604299900563680491964215291720468360933456681005593307187729279478018539532102837247060040450789168837047742882484655150731188613373706854145363872001885815654186972492841075619196485090216542847074922791386068648687399184582403554320117303153178588095463812872354300214532980928150374681897550358290689615020883772588218387143725124660254095748926982159934321361143271090861833
sum1 = 309575642078438773208947649750793560438038690144069550000470706236111082406
sum2 = 303394719183577651416751448350927044928060280972644968966068528268042222965
n = 4597063839057338886607228486569583368669829061896475991448013970518668754752831268343529061846220181652766402988715484221563478749446497476462877699249731
c = 3253873276452081483545152055347615580632252871708666807881332670645532929747667442194685757039215506084199053032613562932819745309368748317106660561209205

for i1 in trange(0, 1000):
    for i2 in range(0, 1000):
        k1 = i1 + 1000 * sum1
        k2 = i2 + 1000 * sum2
        tmp = gcd(m1 - k1, m2 - k2)
        if int(tmp).bit_length() == 256:
                print(tmp)
                p = tmp + 1
                q = n // p
                phi = (p - 1) * (q - 1)
                d = pow(e, -1, phi)
                m = pow(c, d, n)
                print(long_to_bytes(m))
                exit()
                
```

### 12. ez_factor_4

---

**__chall.py__**

```py
from Crypto.Util.number import *
from Crypto.Util.Padding import *
from Crypto.Cipher import AES
from hashlib import sha256
from random import *
from secret import flag

p = getPrime(256)
q = getPrime(256)
n = p*q
phi = (p-1)*(q-1)
e = 65537
d = inverse(e,phi)

key = sha256(str(p+q).encode()).digest()
enc = AES.new(key, AES.MODE_ECB)
c = enc.encrypt(pad(flag,16))
hint = getPrime(20)*d**3 + getPrime(128)*phi**2

print("n =",n)
print("c =",c)
print("hint =",hint)

'''
n = 8218998145909849489767589224752145194323996231101223014114062788439896662892324765430227087699807011312680357974547103427747626031176593986204926098978521
c = b'\x9a \x8f\x96y-\xb4\tM\x1f\xe6\xcc\xef\xd5\x19\xf26`|B\x10N\xd7\xd0u\xafH\x8d&\xe3\xdbG\x13\x8e\xea\xc0N\n\r\x91\xdc\x95\x9b\xb1Ny\xc1\xc4'
hint = 1860336365742538749239400340012599905091601221664081527583387276567734082070898348249407548568429668674672914754714801138206452116493106389151588267356258514501364109988967005351164279942136862087633991319071449095868845225164481135177941404709110974226338184970874613912364483762845606151111467768789248446875083250614540611690257121725792701375153027230580334095192816413366949340923355547691884448377941160689781707403607778943438589193122334667641037672649189861
'''
```
---

#### 1. Tổng quan

+ Vẫn giống như các bài trước nhưng `leak = getPrime(20)*d**3 + getPrime(128)*phi**2`

### 2. Solution

`hint = getPrime(20)*d**3 + getPrime(128)*phi**2`

`d = pow(e, -1, phi)` -> $e *d = 1 + k * phi$
```py
h * e ** 3 = a * (1 + k * phi) ** 3 + e ** 3 * b * phi ** 2
h * e ** 3 = a * (1 + 3 * (k * phi) ** 2 + 3 * k * phi + (k * phi) ** 3) + e ** 3 * b * phi ** 2
```

$h * {e ^ } - a = k * phi$

Do a là số prime 20 bit nên ta có thể brute tìm lại số a bằng cách kiểm tra $2 ^ {h * e ^ 3 - a} \pmod{n}$.
khi đó ta có thểm tìm ra k * phi rồi áp dụng cách tương tự bài 1 để giải

#### 3. Code

```py

from tqdm import *
from Crypto.Util.number import *
from Crypto.Util.Padding import *
from Crypto.Cipher import AES
from hashlib import sha256
from math import gcd
from math import isqrt
from random import randrange

from sage.all import is_prime

n = 8218998145909849489767589224752145194323996231101223014114062788439896662892324765430227087699807011312680357974547103427747626031176593986204926098978521
c = b'\x9a \x8f\x96y-\xb4\tM\x1f\xe6\xcc\xef\xd5\x19\xf26`|B\x10N\xd7\xd0u\xafH\x8d&\xe3\xdbG\x13\x8e\xea\xc0N\n\r\x91\xdc\x95\x9b\xb1Ny\xc1\xc4'
hint = 1860336365742538749239400340012599905091601221664081527583387276567734082070898348249407548568429668674672914754714801138206452116493106389151588267356258514501364109988967005351164279942136862087633991319071449095868845225164481135177941404709110974226338184970874613912364483762845606151111467768789248446875083250614540611690257121725792701375153027230580334095192816413366949340923355547691884448377941160689781707403607778943438589193122334667641037672649189861
e = 65537

def erato(n):

    arr = {}
    for i in range(2, n):
        arr[i] = True

    for i in range(2, ceil(sqrt(n))):
        if arr[i]:
            for j in range(i**2, n, i):
                arr[j] = False

    return [i for i in trange(2, n) if (arr[i] and int(i).bit_length() == (int(n).bit_length() - 1))]

lst = erato(2 ** 20)

i = 0
for k in lst:
    tmp = pow(2, hint * (e ** 3) - k, n) - 1
    if not tmp:
        kphi = hint * (e ** 3) - k

        p = gcd(pow(2, kphi // (3 ** 3), n) - 1, n)
        q = n // p
        key = sha256(str(p+q).encode()).digest()
        enc = AES.new(key, AES.MODE_ECB)
        print(enc.decrypt(c))
        exit()
```

### 13. ez_mod

```py
from Crypto.Util.number import *
from random import *

table = "01234567"
p = getPrime(328)
flag = b"NSSCTF{" + "".join([choice(table) for i in range(70)]).encode() + b"}"
c = bytes_to_long(flag) % p

print("p =",p)
print("c =",c)

'''
p = 501785758961383005891491265699612686883993041794260611346802080899615437298977076093878384543577171
c = 327005346153237517234971706274055111857447948791422192829214537757745905845319188257204611848165263
'''

```

#### 1. Tổng quan

+ có flag là một chuỗi số ngẫu nhiên `flag = b"NSSCTF{" + "".join([choice(table) for i in range(70)]).encode() + b"}"` với `table = "01234567"`
và ta có kết quả của flag % p

#### 2. Solution

Do flag được chuyển từ bytes sang số nên ta có thể viết được như sau:
+ $m = \sum_{i = 0}{flag[i] * 256 ^ i} \pmod{p}$

do các flag[i] khá nhỏ và liên tục từ [48, 55] nên mình sử dụng solve_linear_mod để tìm lại flag. Nhưng do có khá nhiều hệ số nên hơi khó ra và phần bound phải đặt nhỏ hơn phần bound thực tế thì mới ra được kết quả

#### 3. Code

```py

from collections.abc import Sequence
import math
import operator
from typing import List, Tuple
from sage.all import ZZ, gcd, matrix, prod, var


def _process_linear_equations(equations, vars, guesses) -> List[Tuple[List[int], int, int]]:
    result = []

    for rel, m in equations:
        op = rel.operator()
        if op is not operator.eq:
            raise TypeError(f"relation {rel}: not an equality relation")

        expr = (rel - rel.rhs()).lhs().expand()
        for var in expr.variables():
            if var not in vars:
                raise ValueError(f"relation {rel}: variable {var} is not bounded")

        # Fill in eqns block of B
        coeffs = []
        for var in vars:
            if expr.degree(var) >= 2:
                raise ValueError(f"relation {rel}: equation is not linear in {var}")
            coeff = expr.coefficient(var)
            if not coeff.is_constant():
                raise ValueError(f"relation {rel}: coefficient of {var} is not constant (equation is not linear)")
            if not coeff.is_integer():
                raise ValueError(f"relation {rel}: coefficient of {var} is not an integer")

            coeffs.append(int(coeff) % m)

        # Shift variables towards their guesses to reduce the (expected) length of the solution vector
        const = expr.subs({var: guesses[var] for var in vars})
        if not const.is_constant():
            raise ValueError(f"relation {rel}: failed to extract constant")
        if not const.is_integer():
            raise ValueError(f"relation {rel}: constant is not integer")

        const = int(const) % m

        result.append((coeffs, const, m))

    return result


def solve_linear_mod(equations, bounds, verbose=False, **lll_args):
    """Solve an arbitrary system of modular linear equations over different moduli.

    equations: A sequence of (lhs == rhs, M) pairs, where lhs and rhs are expressions and M is the modulus.
    bounds: A dictionary of {var: B} entries, where var is a variable and B is the bounds on that variable.
        Bounds may be specified in one of three ways:
        - A single integer X: Variable is assumed to be uniformly distributed in [0, X] with an expected value of X/2.
        - A tuple of integers (X, Y): Variable is assumed to be uniformly distributed in [X, Y] with an expected value of (X + Y)/2.
        - A tuple of integers (X, E, Y): Variable is assumed to be bounded within [X, Y] with an expected value of E.
        All variables used in the equations must be bounded.
    verbose: set to True to enable additional output
    lll_args: Additional arguments passed to LLL, for advanced usage.

    NOTE: Bounds are *soft*. This function may return solutions above the bounds. If this happens, and the result
    is incorrect, make some bounds tighter and try again.

    Tip: if you get an unwanted solution, try setting the expected values to that solution to force this function
    to produce a different solution.

    Tip: if your bounds are loose and you just want small solutions, set the expected values to zero for all
    loosely-bounded variables.

    >>> k = var('k')
    >>> # solve CRT
    >>> solve_linear_mod([(k == 2, 3), (k == 4, 5), (k == 3, 7)], {k: 3*5*7})
    {k: 59}

    >>> x,y = var('x,y')
    >>> solve_linear_mod([(2*x + 3*y == 7, 11), (3*x + 5*y == 3, 13), (2*x + 5*y == 6, 143)], {x: 143, y: 143})
    {x: 62, y: 5}

    >>> x,y = var('x,y')
    >>> # we can also solve homogenous equations, provided the guesses are zeroed
    >>> solve_linear_mod([(2*x + 5*y == 0, 1337)], {x: 5, y: 5}, guesses={x: 0, y: 0})
    {x: 5, y: -2}
    """

    # The general idea is to set up an integer matrix equation Ax=y by introducing extra variables for the quotients,
    # then use LLL to solve the equation. We introduce extra axes in the lattice to observe the actual solution x,
    # which works so long as the solutions are known to be bounded (which is of course the case for modular equations).
    # Scaling factors are configured to generally push the smallest vectors to have zeros for the relations, and to
    # scale disparate variables to approximately the same base.

    vars = list(bounds)
    guesses = {}
    var_scale = {}
    for var in vars:
        bound = bounds[var]
        if isinstance(bound, Sequence):
            if len(bound) == 2:
                xmin, xmax = map(int, bound)
                guess = (xmax - xmin) // 2 + xmin
            elif len(bound) == 3:
                xmin, guess, xmax = map(int, bound)
            else:
                raise TypeError("Bounds must be integers, 2-tuples or 3-tuples")
        else:
            xmin = 0
            xmax = int(bound)
            guess = xmax // 2
        if not xmin <= guess <= xmax:
            raise ValueError(f"Bound for variable {var} is invalid ({xmin=} {guess=} {xmax=})")
        var_scale[var] = max(xmax - guess, guess - xmin, 1)
        guesses[var] = guess

    var_bits = math.log2(int(prod(var_scale.values()))) + len(vars)
    mod_bits = math.log2(int(prod(m for rel, m in equations)))
    if verbose:
        print(f"verbose: variable entropy: {var_bits:.2f} bits")
        print(f"verbose: modulus entropy: {mod_bits:.2f} bits")

    # Extract coefficients from equations
    equation_coeffs = _process_linear_equations(equations, vars, guesses)

    is_inhom = any(const != 0 for coeffs, const, m in equation_coeffs)

    NR = len(equation_coeffs)
    NV = len(vars)
    if is_inhom:
        # Add one dummy variable for the constant term.
        NV += 1
    B = matrix(ZZ, NR + NV, NR + NV)

    # B format (rows are the basis for the lattice):
    # [ mods:NRxNR 0
    #   eqns:NVxNR vars:NVxNV ]
    # eqns correspond to equation axes, fi(...) = yi mod mi
    # vars correspond to variable axes, which effectively "observe" elements of the solution vector (x in Ax=y)
    # mods and vars are diagonal, so this matrix is lower triangular.

    # Compute maximum scale factor over all variables
    S = max(var_scale.values())

    # Compute equation scale such that the bounded solution vector (equation columns all zero)
    # will be shorter than any vector that has a nonzero equation column
    eqS = S << (NR + NV + 1)
    # If the equation is underconstrained, add additional scaling to find a solution anyway
    if var_bits > mod_bits:
        eqS <<= int((var_bits - mod_bits) / NR) + 1
    col_scales = []

    for ri, (coeffs, const, m) in enumerate(equation_coeffs):
        for vi, c in enumerate(coeffs):
            B[NR + vi, ri] = c
        if is_inhom:
            B[NR + NV - 1, ri] = const
        col_scales.append(eqS)
        B[ri, ri] = m

    # Compute per-variable scale such that the variable axes are scaled roughly equally
    for vi, var in enumerate(vars):
        col_scales.append(S // var_scale[var])
        # Fill in vars block of B
        B[NR + vi, NR + vi] = 1

    if is_inhom:
        # Const block: effectively, this is a bound of 1 on the constant term
        col_scales.append(S)
        B[NR + NV - 1, -1] = 1

    if verbose:
        print("verbose: scaling shifts:", [math.log2(int(s)) for s in col_scales])
        print("verbose: unscaled matrix before:")
        print(B.n())

    for i, s in enumerate(col_scales):
        B[:, i] *= s
    B = B.LLL(**lll_args)
    for i, s in enumerate(col_scales):
        B[:, i] /= s

    # Negate rows for more readable output
    for i in range(B.nrows()):
        if sum(x < 0 for x in B[i, :]) > sum(x > 0 for x in B[i, :]):
            B[i, :] *= -1
        if is_inhom and B[i, -1] < 0:
            B[i, :] *= -1

    if verbose:
        print("verbose: unscaled matrix after:")
        print(B.n())

    for row in B:
        if any(x != 0 for x in row[:NR]):
            # invalid solution: some relations are nonzero
            continue

        if is_inhom:
            # Each row is a potential solution, but some rows may not carry a constant.
            if row[-1] != 1:
                if verbose:
                    print(
                        "verbose: zero solution",
                        {var: row[NR + vi] for vi, var in enumerate(vars) if row[NR + vi] != 0},
                    )
                continue

        res = {}
        for vi, var in enumerate(vars):
            res[var] = row[NR + vi] + guesses[var]

        return res
def eval_bytes(f):
    return sum([j * 256 ** i for i, j in enumerate(f[::-1])])
from Crypto.Util.number import *
p = 501785758961383005891491265699612686883993041794260611346802080899615437298977076093878384543577171
c = 327005346153237517234971706274055111857447948791422192829214537757745905845319188257204611848165263

table = [i for i in b"01234567"]

x = [var(f"flag_{i}") for i in range(70)]
f = [i for i in b"NSSCTF{"] + x + [ord("}")]

f = eval_bytes(f)
bound = {i: [50, 53] for i in x}
flag = "".join([chr(i) for i in solve_linear_mod([(f == c, p)], bound).values()])
print("NSSCTF{" + flag + "}")
```

### 14. ez_mod_1
```py
from Crypto.Util.number import *
from random import *

table = "01234567"
p = getPrime(328)
flag = b"NSSCTF{" + "".join([choice(table) for i in range(80)]).encode() + b"}"
c = bytes_to_long(flag) % p

print("p =",p)
print("c =",c)
print(flag)

'''
p = 324556397741108806830285502585098109678766437252172614832253074632331911859471735318636292671562523
c = 141624663734155235543198856069652171779130720945875442624943917912062658275440028763836569215230250
'''

```

#### 1. Tổng quan
+ Cũng khá tương tự bài trên nhưng lần này flag đã dài hơn

#### 2. Solution

+ Do flag gồm nhiều số hơn nên solve linear không trả ra được kết quả đúng nữa nên mình có thử sử dụng code của blupper nhưng vẫn không ra nên đành ngồi code tay.
+ Ta vẫn có + $m = \sum_{i = 0}{flag[i] * 256 ^ i} \pmod{p}$ do 48 < flag < 55
nên mình cộng thêm vào
+ $m = \sum_{i = 0}{(52 + x_i) * 256 ^ i} \pmod{p}$ khi đó x_i = [-4, 3]

$$
\begin{pmatrix}
x_0 & x_1 & \ldots & x_i & \ldots & x_{79} & 1 & k \\
\end{pmatrix}
\begin{pmatrix}
1 & 0 & \ldots & 0 & \ldots & 0 & 0 & 256^{80} \\
0 & 1 & \ldots & 0 & \ldots & 0 & 0 & 256^{79} \\
\vdots & \vdots & \ddots & \vdots & \ddots & \vdots & \vdots & \vdots \\
0 & 0 & \ldots & 1 & \ldots & 0 & 0 & 256^{80-i} \\
\vdots & \vdots & \ddots & \vdots & \ddots & \vdots & \vdots & \vdots \\
0 & 0 & \ldots & 0 & \ldots & 1 & 0 & 256^1 \\
0 & 0 & \ldots & 0 & \ldots & 0 & 1 & t-c \\
0 & 0 & \ldots & 0 & \ldots & 0 & 0 & p
\end{pmatrix} = 
\begin{pmatrix}
x_0 & x_1 & \ldots & x_i & \ldots & x_{79} & 1 & 0
\end{pmatrix}
$$

với $t = NSSCTF\{ \times 256^{81} + \} + \sum_{i=0}^{80} 52 \times 256^{80-i}$

#### 3. Code

```py

from Crypto.Util.number import *
from tqdm import *

def eval_bytes(f):
    return sum([j * (256 ** i) for i, j in enumerate(f[::-1])])

p = 324556397741108806830285502585098109678766437252172614832253074632331911859471735318636292671562523
c = 141624663734155235543198856069652171779130720945875442624943917912062658275440028763836569215230250

F = PolynomialRing(Zmod(p), [f"x_{i}" for i in range(80)])
x = F.gens()

f = [i for i in b"NSSCTF{"] + [_ + 51 for _ in x] + [ord("}")]
n = 80
f = eval_bytes(f) - c

M = [int(_ %  p) for _ in f.coefficients()[:-1]][::-1] + [int(f.coefficients()[-1])]

M = block_matrix([
    [1, column_matrix(M)],
    [0, matrix([[p]])]
])

M[:, -1] *= 2 ** 100

for line in M.BKZ(block_size=20):
    m = ""
    if line[-1] == 0 and abs(line[-2]) == 1:
        for i in line[:-2]:
            m += chr((51 + i))
        flag = "NSSCTF{" + m[::-1] + "}"
        print(flag)
        break
```

### 15. ez_mod_2

```py
from Crypto.Util.number import *
from random import *

table = "Nss"
p = getPrime(328)
flag = b"NSSCTF{" + "".join([choice(table) for i in range(100)]).encode() + b"}"
c = bytes_to_long(flag) % p

print("p =",p)
print("c =",c)

'''
p = 421384892562377694077340767015240048728671794320496268132504965422627021346504549648945043590200571
c = 273111533929258227142700975315635731051782710899867431150541189647916512765137757827512121549727178
'''
```

#### 1. Tổng quan

+ Bài vẫn như thế nhưng `table = "Nss"` và lên 100 chữ ngẫu nhiên

#### 2. Solution

+ Mình có thử làm giống như bài trước nhưng có vẻ không được vì các vector trả ra không phải là vector ngắn nhất.

với:

$$
\begin{cases}
ord(N) × a + b ≡ 1 \pmod{p} \\
ord(s) × a + b ≡ 0 \pmod{p}
\end{cases}
$$

mình tìm được hệ số a, b sao cho khi nhân với các phần tử kia ta được 0, 1. Khi đó
$c - prefix ≡ x_0 × 256^{100} + x_1 × 256^{99} + ... + x_i × 256^{100-i} + x_{99} × 256 \pmod{p}$ với các x là flag
$(c - prefix)a ≡ ax_0 × 256^{100} + ax_1 × 256^{99} + ... + ax_i × 256^{100-i} + ax_{99} × 256 \pmod{p}$
$(c - prefix)a ≡ ax_0 × 256^{100} + ax_1 × 256^{99} + ... + ax_i × 256^{100-i} + ax_{99} × 256 \pmod{p}$

với (a * x_i + b) = 0, 1 ta có thể thấy đây là bài toán cơ bản và dễ dàng tìm lại được (a * x_i + b) nếu nó bằng 1 thì dód là vị trí của N còn lại là vị trí của s.

#### 3. Code
```py

from Crypto.Util.number import *
from random import *

def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%03d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)
def eval_bytes(f):
    return sum([j * (256 ** i) for i, j in enumerate(f[::-1])])

table = "Nss" # 78, 115
# flag = b"NSSCTF{" + "".join([choice(table) for i in range(100)]).encode() + b"}"

p = 421384892562377694077340767015240048728671794320496268132504965422627021346504549648945043590200571
c = 273111533929258227142700975315635731051782710899867431150541189647916512765137757827512121549727178

M = matrix(GF(p), [
    [ord("N"), 1],
    [ord("s"), 1]
])

N = column_matrix(GF(p), [1, 0])

a, b = [int(_[0]) for _ in M.solve_right(N)]

k = bytes_to_long(b"NSSCTF{") * 256^101 + bytes_to_long(b"}")
k = a * (c - k) % p

for i in range(1, 101):
    k += b * pow(256, i, p) 

M = [pow(256, i , p) for i in range(1, 101)]
M = M[::-1] + [k % p]

M = block_matrix([
    [1, column_matrix(M)],
    [0, matrix([[p]])]
])

M[:, -1] *= 2 ** 100
M = M.BKZ(block_sizes = 20)

for i in M:
    if i[-1] == 0 and i[-2] == 1:
        print(i)
        m = ""
        for _ in i[:-2]:
            if _ == 0:
                m += "N"
            else:
                m += "s"
        print("NSSCTF{" + m + "}")
        break
```

### 16. ez_mod_3

```py
from Crypto.Util.number import *
from random import *

p = 382341578876755047910270786090569535013570954958220282576527310027607029356817834229805565170363061
table1 = "NsS"
table2 = [363240026866636825072669542082311717933742315917012606686823760007829170314055842025699242629919061, 353526073204447024446020739384656942280539226749705781536551943704760671350652481846175115676519925, 343812119542257223819371936687002166627336137582398956386280127401692172387249121666650988723120789]
choose = [choice(table1) for i in range(100)]

flag = b"NSSCTF{" + "".join(choose).encode() + b"}"
c = 0
for i in range(len(choose)):
    c += 256**i*table2[table1.index(choose[i])]
    c %= p

print("c =",c)

'''
c = 207022199908418203957326448601855685285890830964132201922954241454827344173832839490247666897642796
'''
```

#### 1. Tổng quan

+ bài có hơi thay đổi một chút nhưng vẫn tương tự bài trên thôi.

#### 2. Code

```py   
from Crypto.Util.number import *
from random import *

p = 382341578876755047910270786090569535013570954958220282576527310027607029356817834229805565170363061
table1 = "NsS"
table2 = [363240026866636825072669542082311717933742315917012606686823760007829170314055842025699242629919061, 353526073204447024446020739384656942280539226749705781536551943704760671350652481846175115676519925, 343812119542257223819371936687002166627336137582398956386280127401692172387249121666650988723120789]
choose = [choice(table1) for i in range(100)]

flag = b"NSSCTF{" + "".join(choose).encode() + b"}"
c = 0

for i in range(len(choose)):
    c += 256**i*table2[table1.index(choose[i])]
    c %= p

c = 207022199908418203957326448601855685285890830964132201922954241454827344173832839490247666897642796

"""

[c0, 1, 1]
[c1, 1, 1]
[c2, 1, 1]

[-1, 0, 1]
"""

A = matrix(GF(p), [
    [table2[0], 1],
    [table2[1], 1],
    [table2[2], 1]
])

B = column_matrix(GF(p), [1, 0, -1])

a, b = [int(_[0]) for _ in A.solve_right(B)]

c = a * c % p

for i in range(100):
    c += b * (pow(256, i, p))
    
M = column_matrix([pow(256, i, p) for i in range(100)] + [-c % p])

M = block_matrix([
    [1, M],
    [0, matrix([[p]])]
])

M[:, -1] *=  2 ** 100

M = M.BKZ(block_sizes = 20)

for i in M:
    if i[-1] == 0 and i[-2] == 1:
        print(i)
        m = ""
        
        for _ in i[:-2]:
            if _ == 1:
                m += table1[0]
            elif _ == 0:
                m += table1[1]
            elif _ == -1:
                m += table1[2]
                
        print("NSSCTF{" + m + "}")
        break
```
