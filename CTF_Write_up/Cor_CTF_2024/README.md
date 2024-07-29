
Tables_of_contens
================

## COR_CTF_2024_Crypto

**Mình viết dựa trên nhiều solution của người khác do mình trong giải này không có làm được nhiều(làm tư liệu tham khảo) cũng như tìm hiểu thêm về các bài sau giải**

### 1. Steps

---

**_main.py_**:

```py
from Crypto.Util.number import getPrime
from random import randint
from hashlib import sha512
from secret import FLAG

p = getPrime(1024)

Pair = tuple[int, int]

def apply(x: Pair, y: Pair) -> Pair:
    z0 = x[0] * y[1] + x[1] * y[0] - x[0] * y[0]
    z1 = x[0] * y[0] + x[1] * y[1]
    return z0 % p, z1 % p

def calculate(n: int) -> Pair:
    out = 0, 1
    base = 1, 1

    while n > 0:
        if n & 1 == 1: out = apply(out, base)
        n >>= 1
        base = apply(base, base)

    return out

def step(x: Pair, n: int):
    '''Performs n steps to x.'''
    return apply(x, calculate(n))

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(a, b))

def main() -> None:
    g = tuple(randint(0, p - 1) for _ in range(2))
    a = randint(0, p)
    b = randint(0, p)

    A = step(g, a)
    B = step(g, b)

    print(p)
    print(g)
    print(A)
    print(B)

    shared = step(A, b)
    assert shared == step(B, a)

    pad = sha512(str(shared).encode()).digest()
    print(xor(FLAG, pad))

if __name__ == "__main__":
    main()

```

**_output.txt_**:

```py
140323158913416495607520736187548995477774864895449373468435168606940894555091715325755245563618777520381345121826124291879072024129139794758353829170487152290036863771427918014687523291663877491666410660298255515196964873944928956895167652588843616727666115196647426152811435167407394960435891152283442366721
(96065253104055475368515351480749372850658086665031683689391433619786525841252022013348418216780129963411710917302022475212035579772549622047772413277044476931991100469638284113901919733675144788049607999711496364391389612383885735460390196619821411998848060208912802838145365054170790882835846039461477718592, 99241616571709523646659145402511086659276737895777010655080069795289409091105858433710404513588065826008320709508748555232998727290258965620812790826701703542423766306117851146140634247906095481346444357123297761881438234083584836393572339820023598801127329326758926529813665950889866710376403818615042210724)
(70755695722452190644681854912493449110123792967984325777144153291795297730471865203878351550134745747839905472832417565386100721034554991782211134122667955909129461935072670637104557733518048519759925441567454988894610693095988261459294358350906447578625319131211019007537053689563772428590632011546870587548, 67209626648557152207459211543890871397518255584981755641031188457446084495247511864090204533159666638951190009379067537952490757956859052998865712873197974689323985952177932343928382624951392835548222455898153557185369330197085287972647654361464363270469055087587755117442462138962625643131163131541853061105)
(112356264561144892053527289833892910675229600209578481387952173298070535545532140474473984252645999236867287593260325203405225799985387664655169620807429202440801811880698414710903311724048492305357174522756960623684589130082192061927190750200168319419891243856185874901350055033712921163239281745750477183871, 53362886892304808290625786352337191943295467155122569556336867663859530697649464591551819415844644455424276970213068575695727349121464360678240605137740996864232092508175716627306324344248722088013523622985501843963007084915323781694266339448976475002289825133821073110606693351553820493128680615728977879615)
b'\xbaH\xca[V\xdf\xbb0d2jN"\x9d$e\xec\xe0M\x00\xdb\xf0\x8f\x99f\xc5\n\x8a\xc2h\xa7\xa7'
```

---

#### Tổng quát

Đây là một bài có form khá giống với chuyển khóa diffe-hellman.

```py
    A = step(g, a)
    B = step(g, b)

    shared = step(A, b)
    assert shared == step(B, a)
```

Mình đã có A, B và cần tìm lại shared.

Ngoài ra có một vài hàm như sau:

```py
def apply(x: Pair, y: Pair) -> Pair:
    z0 = x[0] * y[1] + x[1] * y[0] - x[0] * y[0]
    z1 = x[0] * y[0] + x[1] * y[1]
    return z0 % p, z1 % p
```

+ Hàm này dùng để tính toán bình thường và có thể hiểu nó là nhân ma trận.

+ Hàm `calculate(n: int)` dùng để tính số fibonacci và trả lại là hai số `fibo(n), fibo(n + 1)`
+ `step(x: Pair, n: int)` hàm để nhân ma trận với số fibo.

#### solution

Mình chạy code như này thì dễ thấy:

```py
PR.<x, y> = PolynomialRing(ZZ, 2)
g = (96065253104055475368515351480749372850658086665031683689391433619786525841252022013348418216780129963411710917302022475212035579772549622047772413277044476931991100469638284113901919733675144788049607999711496364391389612383885735460390196619821411998848060208912802838145365054170790882835846039461477718592, 99241616571709523646659145402511086659276737895777010655080069795289409091105858433710404513588065826008320709508748555232998727290258965620812790826701703542423766306117851146140634247906095481346444357123297761881438234083584836393572339820023598801127329326758926529813665950889866710376403818615042210724)


a, b = var("a b")
def apply(x, y):
    z0 = x[0] * y[1] + x[1] * y[0] - x[0] * y[0]
    z1 = x[0] * y[0] + x[1] * y[1]
    return z0, z1

print(apply(g, (x, y)))
```
![image](https://github.com/user-attachments/assets/36198c52-635d-4005-9eda-218889200d72)

Khi đó ta biết có thể đưa về giải hệ phương trình 2 ẩn dạng g * a = A, vì đã biết g, A nên có thể dễ dàng tính ra a(x, y) khi đó x = fibo(n) % p, y = pibo(n + 1) % y

ta không cần phải giải tìm n mà chỉ cần nhân lại B.a(x, y) là có shared.

#### Code

```sage
from Crypto.Util.number import getPrime
from random import randint
from hashlib import sha512
from pwn import xor
Pair = tuple[int, int]

p = 140323158913416495607520736187548995477774864895449373468435168606940894555091715325755245563618777520381345121826124291879072024129139794758353829170487152290036863771427918014687523291663877491666410660298255515196964873944928956895167652588843616727666115196647426152811435167407394960435891152283442366721
g = (96065253104055475368515351480749372850658086665031683689391433619786525841252022013348418216780129963411710917302022475212035579772549622047772413277044476931991100469638284113901919733675144788049607999711496364391389612383885735460390196619821411998848060208912802838145365054170790882835846039461477718592, 99241616571709523646659145402511086659276737895777010655080069795289409091105858433710404513588065826008320709508748555232998727290258965620812790826701703542423766306117851146140634247906095481346444357123297761881438234083584836393572339820023598801127329326758926529813665950889866710376403818615042210724)
A = (70755695722452190644681854912493449110123792967984325777144153291795297730471865203878351550134745747839905472832417565386100721034554991782211134122667955909129461935072670637104557733518048519759925441567454988894610693095988261459294358350906447578625319131211019007537053689563772428590632011546870587548, 67209626648557152207459211543890871397518255584981755641031188457446084495247511864090204533159666638951190009379067537952490757956859052998865712873197974689323985952177932343928382624951392835548222455898153557185369330197085287972647654361464363270469055087587755117442462138962625643131163131541853061105)
B = (112356264561144892053527289833892910675229600209578481387952173298070535545532140474473984252645999236867287593260325203405225799985387664655169620807429202440801811880698414710903311724048492305357174522756960623684589130082192061927190750200168319419891243856185874901350055033712921163239281745750477183871, 53362886892304808290625786352337191943295467155122569556336867663859530697649464591551819415844644455424276970213068575695727349121464360678240605137740996864232092508175716627306324344248722088013523622985501843963007084915323781694266339448976475002289825133821073110606693351553820493128680615728977879615)
enc = b'\xbaH\xca[V\xdf\xbb0d2jN"\x9d$e\xec\xe0M\x00\xdb\xf0\x8f\x99f\xc5\n\x8a\xc2h\xa7\xa7'

def apply(x: Pair, y: Pair) -> Pair:
    z0 = x[0] * y[1] + x[1] * y[0] - x[0] * y[0]
    z1 = x[0] * y[0] + x[1] * y[1]
    return z0, z1
A_ = [[3176363467654048278143793921761713808618651230745326965688636175502883249853836420361986296807935862596609792206726080020963147517709343573040377549657226610432665836479567032238714514230950693296836357411801397490048621699699100933182143200202186802279269117846123691668300896719075827540557779153564492132, 96065253104055475368515351480749372850658086665031683689391433619786525841252022013348418216780129963411710917302022475212035579772549622047772413277044476931991100469638284113901919733675144788049607999711496364391389612383885735460390196619821411998848060208912802838145365054170790882835846039461477718592], [96065253104055475368515351480749372850658086665031683689391433619786525841252022013348418216780129963411710917302022475212035579772549622047772413277044476931991100469638284113901919733675144788049607999711496364391389612383885735460390196619821411998848060208912802838145365054170790882835846039461477718592, 99241616571709523646659145402511086659276737895777010655080069795289409091105858433710404513588065826008320709508748555232998727290258965620812790826701703542423766306117851146140634247906095481346444357123297761881438234083584836393572339820023598801127329326758926529813665950889866710376403818615042210724]]

A_ = matrix(Zmod(p), A_)
A = vector(Zmod(p), A)
# B = vector(Zmod(p), B)

a = A_.solve_right(A)

shared = apply(B, a)

pad = sha512(str(shared).encode()).digest()
print(xor(enc, pad))

```
### 2. anglerfish and monkfish

+ source `anglerfish`

---

**_server.py_**:

```py
#!/usr/bin/sage

import sys
print("I caught an anglerfish in the sea! ")
sys.stdout.flush()

from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from random import SystemRandom
import ast

n = 100
m = 100
q = 5
FF.<x> = GF(q)

def apply(F, v):
    out = []
    for i in range(m):
        out.append((v.T * F[i] * v)[0, 0])
    return matrix(FF, m, 1, out)

def apply_verif_info(F, a, b):
    out = []
    for i in range(m):
        out.append((a.T * (F[i] + F[i].T) * b)[0, 0])
    return matrix(FF, m, 1, out)

def create_pok(v, s, F):
    proofs = []
    for i in range(64):
        t = matrix(FF, n, 1, [FF.random_element() for i in range(n)])
        com = apply(F, t)
        verif = apply_verif_info(F, t, s)
        a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
        proofs.append((com, t - a * s, verif))
    return proofs

def verif_pok(v, F, pis):
    coms = []
    for pi in pis:
        com = pi[0]
        assert com not in coms
        coms.append(com)
        resp = pi[1]
        verif = pi[2]
        a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
        out1 = apply(F, resp)
        out2 = com + (a * a) * v - a * verif
        assert out1 == out2

rng = SystemRandom()
gen_seed = []

for i in range(64):
    gen_seed.append(rng.randint(0, 255))

init_seed = gen_seed
gen_seed = bytes(gen_seed)

F = []

for i in range(m):
    cur = []
    for j in range(n):
        cur.append([])
        for k in range(n):
            cur[-1].append(list(FF)[sha256(gen_seed).digest()[0] % len(list(FF))])
            gen_seed = sha256(gen_seed).digest()
    F.append(matrix(FF, n, n, cur))

s = random_matrix(FF, n, 1)

v = apply(F, s)

pok = create_pok(v, s, F)
verif_pok(v, F, pok)

for pi in pok:
    print("m0 =", [list(FF).index(i[0]) for i in list(pi[0])])
    print("m1 =", [list(FF).index(i[0]) for i in list(pi[1])])
    print("m2 =", [list(FF).index(i[0]) for i in list(pi[2])])

print("Can you catch an anglerfish? ")
print("seed =", [int(i) for i in init_seed])
print("v =", [list(FF).index(i[0]) for i in v])

pis = []
for x in range(64):
    m0 = [int(i) for i in ast.literal_eval(input("m0 = "))]
    m1 = [int(i) for i in ast.literal_eval(input("m1 = "))]
    m2 = [int(i) for i in ast.literal_eval(input("m2 = "))]

    for pi in pok:
        assert(m0 != [list(FF).index(i[0]) for i in list(pi[0])])
        assert(m1 != [list(FF).index(i[0]) for i in list(pi[1])])
        assert(m2 != [list(FF).index(i[0]) for i in list(pi[2])])

    m0 = matrix(FF, m, 1, [list(FF)[i] for i in m0])
    m1 = matrix(FF, n, 1, [list(FF)[i] for i in m1])
    m2 = matrix(FF, m, 1, [list(FF)[i] for i in m2])

    assert m0 not in [pi[0] for pi in pok]
    assert m1 not in [pi[1] for pi in pok]
    assert m2 not in [pi[2] for pi in pok]

    pi = (m0, m1, m2)
    pis.append(pi)

verif_pok(v, F, pis)

with open("flag.txt", "r") as f:
    print(f.read())
```

---

+ source `monkfish`

---

**_server.py_**

```py
#!/usr/bin/sage

import sys
print("I caught a monkfish in the sea! ")
sys.stdout.flush()

from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from random import SystemRandom
import ast

n = 100
m = 100
q = 5
FF.<x> = GF(q)


def apply(F, v):
    out = []
    for i in range(m):
        out.append((v.T * F[i] * v)[0, 0])
    return matrix(FF, m, 1, out)

def apply_verif_info(F, a, b):
    out = []
    for i in range(m):
        out.append((a.T * (F[i] + F[i].T) * b)[0, 0])
    return matrix(FF, m, 1, out)

def create_pok(v, s, F):
    t = matrix(FF, n, 1, [FF.random_element() for i in range(n)])
    com = apply(F, t)
    verif = apply_verif_info(F, t, s)
    a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
    return (com, t - a * s, verif)

def verif_pok(v, F, pi):
    com = pi[0]
    resp = pi[1]
    verif = pi[2]
    a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
    out1 = apply(F, resp)
    out2 = com + (a * a) * v - a * verif
    return out1 == out2

rng = SystemRandom()
gen_seed = []

for i in range(64):
    gen_seed.append(rng.randint(0, 255))

init_seed = gen_seed
gen_seed = bytes(gen_seed)

F = []

for i in range(m):
    cur = []
    for j in range(n):
        cur.append([])
        for k in range(n):
            cur[-1].append(list(FF)[sha256(gen_seed).digest()[0] % len(list(FF))])
            gen_seed = sha256(gen_seed).digest()
    F.append(matrix(FF, n, n, cur))

s = random_matrix(FF, n, 1)

v = apply(F, s)

pok = create_pok(v, s, F)
assert verif_pok(v, F, pok)

print("m0 =", [list(FF).index(i[0]) for i in list(pok[0])])
print("m1 =", [list(FF).index(i[0]) for i in list(pok[1])])
print("m2 =", [list(FF).index(i[0]) for i in list(pok[2])])

print("Can you catch a monkfish? ")
print("seed =", [int(i) for i in init_seed])
print("v =", [list(FF).index(i[0]) for i in v])
m0 = [int(i) for i in ast.literal_eval(input("m0 = "))]
m1 = [int(i) for i in ast.literal_eval(input("m1 = "))]
m2 = [int(i) for i in ast.literal_eval(input("m2 = "))]

assert(m0 != [list(FF).index(i[0]) for i in list(pok[0])])
assert(m1 != [list(FF).index(i[0]) for i in list(pok[1])])
assert(m2 != [list(FF).index(i[0]) for i in list(pok[2])])

m0 = matrix(FF, m, 1, [list(FF)[i] for i in m0])
m1 = matrix(FF, n, 1, [list(FF)[i] for i in m1])
m2 = matrix(FF, m, 1, [list(FF)[i] for i in m2])
pi = (m0, m1, m2)

res = verif_pok(v, F, pi)
assert res == True

with open("flag.txt", "r") as f:
    print(f.read())
```
---

Đây là hai bài có cách giải giống nhau nên gộp chung 1 bài luôn.

#### Tổng quan

Bỏ qua các hàm khác có vể khá rườm ra và không quan trọng lắm thì hàm quan trọng nhất như sau

```
def create_pok(v, s, F):
    proofs = []
    for i in range(64):
        t = matrix(FF, n, 1, [FF.random_element() for i in range(n)])
        com = apply(F, t)
        verif = apply_verif_info(F, t, s)
        a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
        proofs.append((com, t - a * s, verif))
    return proofs
```

dễ thấy:
+ Mình đã có `seed` và `v` từ đề cho nên có thể dễ dàng tính lại `F`.
+ com = `apply(F, t)` = `t.T * F[i] * t`
+ a = `list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]` -> a $\in$ [0, 4]
+ resp = `t - a * s`
+ verif = `t.T * (F[i] + F[i].T) * s`

#### Solution

vì a $\in$ [0, 4] nên a hoàn toàn có thể bằng 0 khi đó:
+ `a = 0` -> resp = `t` -> verif = `resp.T * (F[i] + F[i].T) * s`

Ta đã có `verif`, `resp`, `F` điều này tương đương với việc ta có 100 phương trình bậc 1, 100 ẩn nên có thể tính được `s`. Khi có `s` thì sử dụng hàm `create_pok(v, s, F)` để tìm ra các cái proofs mới và hoàn thành chall.

#### Code

```py
from pwn import *
import ast
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from random import SystemRandom
from tqdm import *

n = 100
m = 100
q = 5
FF.<x> = GF(q)

def apply(F, v):
    out = []
    for i in range(m):
        out.append((v.T * F[i] * v)[0, 0])
    return matrix(FF, m, 1, out)

def apply_verif_info(F, a, b):
    out = []
    for i in range(m):
        out.append((a.T * (F[i] + F[i].T) * b)[0, 0])
    return matrix(FF, m, 1, out)


def create_pok(v, s, F):
    proofs = []
    for i in range(64):
        t = matrix(FF, n, 1, [FF.random_element() for i in range(n)])
        com = apply(F, t)
        verif = apply_verif_info(F, t, s)
        a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
        proofs.append((com, t - a * s, verif))
    return proofs

def verif_pok(v, F, pis):
    coms = []
    for pi in pis:
        com = pi[0]
        assert com not in coms
        coms.append(com)
        resp = pi[1]
        verif = pi[2]
        a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
        out1 = apply(F, resp)
        out2 = com + (a * a) * v - a * verif
        assert out1 == out2


io = remote("be.ax",  "31106")
def recv_array() :
    m = io.recvline()[:-1].decode()
    m = m.split('=')[1].strip()
    m = ast.literal_eval(m)
    return m

pis = []
print(io.recvline())
for x in range(64) : 
    m0 = recv_array()
    m1 = recv_array()
    m2 = recv_array()

    pis.append((m0,m1,m2))

print(io.recvline())
seed = recv_array()
v = recv_array()

gen_seed = bytes(seed)
F = []

for i in range(m):
    cur = []
    for j in range(n):
        cur.append([])
        for k in range(n):
            cur[-1].append(list(FF)[sha256(gen_seed).digest()[0] % len(list(FF))])
            gen_seed = sha256(gen_seed).digest()
    F.append(matrix(FF, n, n, cur))

v = Matrix(FF,v)

for p in pis:

	# print(p)
	com = Matrix(FF,p[0])
	verif = Matrix(FF,p[2])

	a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
	if a == 0 :
		print("----------------------------")
		t = matrix(FF, p[1])

		com_ = matrix(apply(F, t.T)).transpose()
		a = list(FF)[sha256(bytes([list(FF).index(i[0]) for i in list(com_) + list(v) + list(verif)])).digest()[0] % len(list(FF))]
		print(com)
		print(list(com_))
		if a == 0:
			lmao = []
			for k in tqdm(range(100)):


				lmao.append((t*(F[k] + F[k].T)).list())

			print(lmao)

			lmao = matrix(FF, lmao)
			secret = matrix(FF, lmao^ -1 * verif.T)

			proof = create_pok(v.T, secret, F)
			print(verif_pok(v.T, F, proof))
			for _ in tqdm(proof):
				m0 = ','.join(map(str, _[0]))
				m1 = ','.join(map(str, _[1]))
				m2 = ','.join(map(str, _[2]))

				io.recvuntil(b"m0 = ")
				io.sendline(m0.encode())
				io.recvuntil(b"m1 = ")
				io.sendline(m1.encode())
				io.recvuntil(b"m2 = ")
				io.sendline(m2.encode())
			io.interactive()
```
