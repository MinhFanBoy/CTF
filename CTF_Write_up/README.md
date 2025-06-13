### Bios_CTF_2025

#### 1. Veiled XOR

**__chall.py__**

```py
from Crypto.Util.number import getPrime, bytes_to_long
n = (p := getPrime(1024)) * (q := getPrime(1024))
print(f"n : {n}\nVeil XOR: {p ^ int(bin(q)[2:][::-1], 2)}")

print(f"{p = }")
print(f"{q = }")
```

Ta có hint là `p ^ int(bin(q)[2:][::-1]`, từ đó ta có

có n = p * q với hướng như sau:

$<----- p$

$<----- q$

có h = p ^ q[::-1] với hướng như sau:

$<----- p$

$-----> q$

khi đó mình thấy nếu biết i bit đầu của p và q. thì mình có thể tính lại tương đương i bit nghịch đảo của p và i bit nghịch đảo của q. Khi đó từ các bit nghich đảo đó mình tìm lại các bit cuối của p và q nếu các bít đó nhân vào và tương ứng với các bit cuối của n thì ta có thể xác nhân được i bit đầu kia là đúng. Từ đó mình thực hiện brute để tìm lại p và q. Mình có thể tối ưu bằng các lưu các bit cuối kia lại để giảm số bit phải brute xuống.

```py
import sys
sys.setrecursionlimit(1 << 30)
n = 25650993834245004720946189793874326497984795849338302417110946799293291648040249066481025511053012034073848003478136002015789778483853455736405270138192685004206122168607287667373629714589814547144217162436740164024414206705483947822707673759856022882063396271521077034396144039740088690783163935477234001508676877728359035563304374705319120303835098697559771353065115371216095633826663393222290375210498159025443467666369652776698531368926392564476840557482790175694984871271075976052162527476586777386578254654222259777299785563550342986250558793337690540798983389913689337683350216697595855274995968459458553148267
c = 7874419222145223100478995004906732383469089972173454594282476506666095078687712494332749473566534625352139353593310707008146533254390514332880136585545606758108380402050369451711762195058199249765633645224407166178729834108159734540770902813439688437621416030538050164358987313607945402928893945400086827254622507315341530235984071126104731692679123171962413857123065243252313290356908958113679070546907527095194888688858140118665219670816655147095649132221436351529029926610142793850463533766705147562234382644751744682744799743855986811769162311342911946128543115444104102909314075691320520722623778914052878038508
l =  26845073698882094013214557201710791833291706601384082712658811014034994099681783926930272036664572532136049856667171349310624166258134687815795133386046337514685147643316723034719743474088423205525505355817639924602251866472741277968741560579392242642848932606998045419509860412262320853772858267058490738386

def reverse_bit(x: int, bit_length: int) -> int:
    """
    Đảo ngược bit của số nguyên x trong độ dài bit cố định.

    Ví dụ: x = 0b110 (6), bit_length = 4 -> 0b0110 (6)
    """
    bin_x = bin(x)[2:].zfill(bit_length)  # chuyển sang nhị phân có độ dài cố định
    reversed_bin = bin_x[::-1]            # đảo chuỗi
    return int(reversed_bin, 2)  

def find(p_ = "1", q_ = "1", i = 1):

    pp = int(p_, 2) << (1024 - i)
    qq = int(q_, 2) << (1024 - i)

    #     return
    if i > 1024:
        return
    
    qqq_low_inv = (pp ^ l) >> (1024 - i)
    qqq = reverse_bit(qqq_low_inv, i)
    
    qq_inv = reverse_bit(int(q_, 2), i)
    ppp = (qq_inv ^ l) % (1 << i)
    if i == 1024:

        if int(q_, 2) * int(p_, 2) == n:
            print(int(q_, 2), int(p_, 2))
        return

    if abs(pp * qq - n) >> (2049 - i) == 0 and (n - ppp * qqq) % (1 << (i)) == 0 :
        find(p_ + "1",q_ + "0", i + 1)
        find(p_ + "0",q_ + "0", i + 1)
        find(p_ + "1",q_ + "1", i + 1)
        find(p_ + "0",q_ + "1", i + 1)
find()
```

```py


c = 7874419222145223100478995004906732383469089972173454594282476506666095078687712494332749473566534625352139353593310707008146533254390514332880136585545606758108380402050369451711762195058199249765633645224407166178729834108159734540770902813439688437621416030538050164358987313607945402928893945400086827254622507315341530235984071126104731692679123171962413857123065243252313290356908958113679070546907527095194888688858140118665219670816655147095649132221436351529029926610142793850463533766705147562234382644751744682744799743855986811769162311342911946128543115444104102909314075691320520722623778914052878038508
n = 25650993834245004720946189793874326497984795849338302417110946799293291648040249066481025511053012034073848003478136002015789778483853455736405270138192685004206122168607287667373629714589814547144217162436740164024414206705483947822707673759856022882063396271521077034396144039740088690783163935477234001508676877728359035563304374705319120303835098697559771353065115371216095633826663393222290375210498159025443467666369652776698531368926392564476840557482790175694984871271075976052162527476586777386578254654222259777299785563550342986250558793337690540798983389913689337683350216697595855274995968459458553148267
l = 26845073698882094013214557201710791833291706601384082712658811014034994099681783926930272036664572532136049856667171349310624166258134687815795133386046337514685147643316723034719743474088423205525505355817639924602251866472741277968741560579392242642848932606998045419509860412262320853772858267058490738386

q = 157175886115186742139959303027405390111861228107102091505766856700095797086341816485855055993388877661141284852225000312517847469930797186236814111356269784359245742317471705804213540358353366912245013088178382086833710204401960847142442441630276194027357377818352292637575305440850409883161953461542938983027 
p = 163199295186073324179797276279944354270549597326329384803395586473622078015363621099666577837677400563335888869623011240415603633416496591704054894101416786193914065379812908164356122894320993324847789836458354626843948047100476949252412558417805001835753637589695324856502771666588833939459265398163032526121

print(bytes.fromhex(hex(pow(c, pow(65537, -1, (p - 1) * (q - 1)), p * q))[2:]))
```

#### 2. Braiding bad


**__chall.py__**

```py
import random
import string
import hashlib
from Crypto.Util.number import bytes_to_long

# message = <REDACTED>

n = 100
Bn = BraidGroup(n)
gs = Bn.gens()
K = 32

gen = gs[n // 2 - 1]
p_list = [gen] + random.choices(gs, k=K-1)
p = prod(p_list)
print(f"p: {list(p.Tietze())}")

a = prod(random.choices(gs[:n//2-2], k=K))
q = a * p * a^-1
print(f"q: {list(q.Tietze())}")

br = prod(random.choices(gs[n//2 + 1:], k=K))
c1 = br * p * br^-1
c2 = br * q * br^-1
h = hashlib.sha512(str(prod(c2.right_normal_form())).encode()).digest()
original_message_len = len(message)
pad_length = len(h) - original_message_len
left_length = random.randint(0, pad_length)
pad1 = ''.join(random.choices(string.ascii_letters, k=left_length)).encode('utf-8')
pad2 = ''.join(random.choices(string.ascii_letters, k=pad_length - left_length)).encode('utf-8')
padded_message = pad1 + message + pad2

d_str = ''.join(chr(m ^^ h) for m, h in zip(padded_message, h))
d = bytes_to_long(d_str.encode('utf-8'))

print(f"c1: {list(c1.Tietze())}")
print(f"c2: {d}")
```

ta có thể dễ dàng tìm lại br bằng 32 phần tử đầu tiên của c1 và từ đó dễ dàng tìm lại flag.

```py
import random
import string
import hashlib
from Crypto.Util.number import *
p = [50, 25, 40, 98, 35, 87, 54, 16, 65, 60, 95, 20, 4, 79, 69, 15, 53, 26, 92, 87, 48, 56, 99, 83, 2, 56, 47, 59, 42, 3, 19, 53]
q = [5, 24, 6, 21, 6, 28, 20, 48, 15, 18, 18, 8, 47, 22, 22, 3, 14, 40, 18, 26, 4, 31, 11, 16, 8, 46, 45, 23, 17, 39, 24, 21, 50, 25, 40, 98, 35, 87, 54, 16, 65, 60, 95, 20, 4, 79, 69, 15, 53, 26, 92, 87, 48, 56, 99, 83, 2, 56, 47, 59, 42, 3, 19, 53, -21, -24, -39, -17, -23, -45, -46, -8, -16, -11, -31, -4, -26, -18, -40, -14, -3, -22, -22, -47, -8, -18, -18, -15, -48, -20, -28, -6, -21, -6, -24, -5]
c1 = [93, 84, 92, 90, 63, 63, 76, 60, 61, 57, 99, 62, 55, 91, 95, 62, 59, 54, 91, 69, 55, 60, 96, 74, 78, 55, 78, 64, 61, 54, 76, 84, 50, 25, 40, 98, 35, 87, 54, 16, 65, 60, 95, 20, 4, 79, 69, 15, 53, 26, 92, 87, 48, 56, 99, 83, 2, 56, 47, 59, 42, 3, 19, 53, -84, -76, -54, -61, -64, -78, -55, -78, -74, -96, -60, -55, -69, -91, -54, -59, -62, -95, -91, -55, -62, -99, -57, -61, -60, -76, -63, -63, -90, -92, -84, -93]

n = 100
Bn = BraidGroup(n)
gs = Bn.gens()
K = 32

p = Bn(p)
q = Bn(q)
br =  Bn(c1[:32])
c1 = Bn(c1)
c2 = br*q*br^-1

r = hashlib.sha512(str(prod(c2.right_normal_form())).encode()).digest()
r = list(r)
c2 =  2315157014596884429538745310505697576231247890652617038454441871904638642633138761681911931668903937398814215580589949726790160298882443329224130590117763020425392822361299940434853674756207376179949432149288134358028
dd = list(long_to_bytes(c2).decode())
# c2 = long_to_bytes(c2)
xx = []
for i in range(len(r)):
    xx.append(chr(ord(dd[i]) ^^ r[i]))
flag = "".join(xx).encode("utf-8")
print(flag)
```


#### 3. DEScent

**__chall.sage__**

```py
#!/usr/bin/env sage
import os, json, random
from hashlib import md5
from Crypto.Cipher import DES

FLAG = os.getenv("FLAG", "bi0sctf{fake_flag}")
randomness = os.urandom(16)
SECRET = os.urandom(16)
server_seed = os.urandom(4)

def gen_rand(user_seed, server_seed):
    return DES.new(user_seed + server_seed, DES.MODE_ECB).encrypt(randomness)

def encode(data):
    P.<x> = ComplexField(128)[]
    poly = 0
    for i in range(len(data)):
        poly += data[i] * x ^ i
    return poly.roots()[1][0]

seen_seeds = set()

for i in range(3):
    try:
        user_input = json.loads(input())
        option = user_input.get("option")
        if option == "get_secret":
            user_seed = os.urandom(4)
            seen_seeds.add(user_seed)
            encoded_secret = encode(SECRET)
            error = encode(gen_rand(user_seed, server_seed))
            print(json.dumps({"encoded_secret": str(encoded_secret + error), "user_seed": user_seed.hex()}))
        elif option == "encode":
            data = bytes.fromhex(user_input.get("data"))
            user_seed = bytes.fromhex(user_input.get("user_seed"))
            if len(data) != 16 or len(user_seed) != 4:
                print(json.dumps({"error": "Invalid input"}))
                continue
            if user_seed in seen_seeds:
                print(json.dumps({"error": "Seed already used"}))
                continue
            seen_seeds.add(user_seed)
            encoded_data = str(encode(data) + encode(gen_rand(user_seed, server_seed)))
            print(json.dumps({"encoded_data": encoded_data}))
        elif option == "verify":
            user_secret = bytes.fromhex(user_input.get("user_secret"))
            if user_secret == SECRET:
                print(json.dumps({"flag": FLAG}))
            else:
                print(json.dumps({"error": "Invalid secret"}))
        else:
            print(json.dumps({"error": "Invalid option"}))
    except Exception as e:
        print(json.dumps({"error": "Invalid input"}))
        continue
```

Trong bài này ta cần từ kết quả của hàm encod để tìm lại đầu vào của nó.

```py
def encode(data):
    P.<x> = ComplexField(128)[]
    poly = 0
    for i in range(len(data)):
        poly += data[i] * x ^ i
    return poly.roots()[1][0]
```

ta có thể viết lại như sau:

$$

0 = \sum_{i = 0}^{15}{{data_i} * {x^i}}

$$

do data trong khoảng [0, 255] nên ta có thể hướng tới LLL để tìm lại. 

$$

0 = \begin{bmatrix}
\text{data}_0 & \text{data}_1 & \cdots & \text{data}_{15}
\end{bmatrix}
\cdot
\begin{bmatrix}
1 \\
x \\
x^2 \\
\vdots \\
x^{15}
\end{bmatrix}

$$


$$

\begin{bmatrix}
x^1 & x^2 & \cdots & 1 \\
1 & 0 & \cdots & 0 \\
0 & 1 & \cdots & 0 \\
\vdots & \vdots & \ddots & \vdots \\
0 & 0 & \cdots & 0 \\
\end{bmatrix}
.T

$$

```py
#!/usr/bin/env sage
import os, json
from hashlib import md5
from Crypto.Cipher import DES
os.environ["TERM"] = "linux"
from pwn import *
from Crypto.Util.number import *

context.log_level = "debug"
def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)
        
P = ComplexField(128)

F = PolynomialRing(ZZ, 'x', 16)
xs = list(F.gens())

def encode(data):
    P.<x> = ComplexField(128)[]
    poly = 0
    for i in range(len(data)):
        poly += data[i] * x ^ i
    print(poly)
    return poly.roots()[1][0]

s = process(['sage', 'chal.sage'])

s.sendline(json.dumps({"option": "get_secret"}))

output1 = eval(s.recvline().decode())

def gen_rand(user_seed, server_seed):
    return DES.new(user_seed + server_seed, DES.MODE_ECB).encrypt(b"\x00" * 16)

def xor(data, key):
    from itertools import cycle
    if len(key) > len(data):
        key = data, data = key
    cycled_key = cycle(key)
    return bytes([b ^^ next(cycled_key) for b in data])


i = P(output1['encoded_secret'])
print(output1["user_seed"])
key = xor(bytes.fromhex(output1["user_seed"]), b"\x01")

s.sendline(json.dumps({"option": "encode", "data": '01' * 15 + '00', "user_seed": (key).hex()}))

output2 = eval(s.recvline().decode())

i -= P(output2["encoded_data"]) - encode(bytes.fromhex('01' * 15 + '00'))


def encode2(i):
    poly = sum(xs[k] * (i) ** k for k in range(16))
    return poly

eqs = []
eq1, eq2 = [], []
ss = [var('s' + str(i)) for i in range(16)]
for i, _ in enumerate((encode2(i)).coefficients()):
    eq1.append((QQ(_.real_part()) ))
    eq2.append((QQ(_.imag_part()) ))
eqs.append(eq1)
eqs.append(eq2)

M = diagonal_matrix([1/(1 << 128)] * 16)
M = block_matrix(QQ,
    [
        [matrix(eqs).T, M]
     ]
)

M = M.LLL()
M *= (1 << 128)

k = (bytes(list(M[0][2:] * sign(M[0][-1]))))
s.sendline(json.dumps({"option": "verify", "user_secret": k.hex()}))
s.interactive()
```

#### 4. apna-AES

**__chall.py__**

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
import json

key = urandom(16)
iv1, iv2 = urandom(16), urandom(16)

class AES_APN:
    def __init__(self):
        self.key = key

    def xor(self, a, b):
        return bytes([x^y for x,y in zip(a,b)])

    def encrypt(self, pt, iv1, iv2):
        blocks = [pt[i:i+16] for i in range(0, len(pt), 16)]
        ct = b""
        state1, state2 = iv1, iv2
        for i in range(len(blocks)):
            block = self.xor(blocks[i], state1)
            cipher = AES.new(self.key, AES.MODE_ECB)
            enc = cipher.encrypt(block)
            ct += self.xor(enc, state2)
            state2 = block
            state1 = enc
        return ct

    def decrypt(self, ct, iv1, iv2):
        blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
        pt = b""
        state1, state2 = iv1, iv2
        for i in range(len(blocks)):
            block = self.xor(blocks[i], state2)
            cipher = AES.new(self.key, AES.MODE_ECB)
            dec = cipher.decrypt(block)
            pt += self.xor(dec, state1)
            state1 = block
            state2 = dec
        try:
            unpad(pt, 16)
        except:
            return "Invalid padding"
        else:
            return "Valid padding"

def main():
    s='''
+----------------------------------------------------------+
|   ◦ APNA-AES v1.0 ◦                                      |
|   > Decryption protocol active                           |
|   > Encryption module: [offline]                         |
+----------------------------------------------------------+
'''
    print(s)
    custom = AES_APN()
    message = open("message.txt","rb").read().strip()
    enc_message = custom.encrypt(pad(message, 16), iv1, iv2)
    token = {"IV1": iv1.hex(), "IV2": iv2.hex(), "ciphertext": enc_message.hex()}
    print(f"Here is the encrypted message : {json.dumps(token)}")
    while True:
        try:
            token = json.loads(input("Enter token: "))
            ct = bytes.fromhex(token["ciphertext"])
            iv1 = bytes.fromhex(token["IV1"])
            iv2 = bytes.fromhex(token["IV2"])
            pt = custom.decrypt(ct, iv1, iv2)
            print("Decryption result: ", json.dumps({"result": pt}))
        except:
            exit(0)

if __name__ == "__main__":
    try:
        main()
    except:
        print("\nBYE")
        exit(0)
```

bài này được chia làm 2 phần, phần đầu có thể dễ thấy ta phải padding oracle attack để tìm lại mật khẩy giải nén file zip. Khi giải nén file ta có đoạn code sau:

```py
from sage.all import *
from hashlib import sha256
from Crypto.Util.number import inverse
import secrets

mask_lsb = (1 << 128) - 1
mask_msb = (1 << 256) - 1

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
E = EllipticCurve(GF(p), [0, 7])
G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def sign(h, k, d):
    kG = k * G
    r = int(kG.x()) % n
    k_inv = inverse(k, n)
    s = (k_inv * (h + r * d)) % n
    return r, s

d = secrets.randbelow(n)
assert d.bit_length() == 256

Q = d * G

h = int(sha256(b"Karmany-evadhikaras te ma phalesu kadacana ma karma-phala-hetur bhur ma te sango 'stv akarmani.").hexdigest(), 16)
k = (h - (h & (pow(2, 128) - 1))) + ((d - (d & (pow(2, 128) - 1))) // pow(2, 128))
r, s = sign(h, k, d)

print(f"Q = ({int(Q.x())}, {int(Q.y())})\n{r = }\n{s = }")
# flag : bi0sCTF{sha256(str(d))}
```

ta cần tìm lại d từ sig đã được cho. Dễ thấy do k được tạo sai cách nên nó có thể dẫn tới lattice attack để tìm lại d

```py

from hashlib import sha256
from Crypto.Util.number import inverse

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Q_x = 75734809163232403156751567099323868969251536315520212930406362087044311009812
Q_y = 59376216810615307969183220664321477461374978580814681880833956961200252954411
r = 75188570313431311860804303251549254089807291132108761029130443888999271228837
s = 28425244802253213823226413962559295239693382541446853572606143356013575587849

E = EllipticCurve(GF(p), [0, 7])
G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
Q = E(Q_x, Q_y)

h = int(sha256(b"Karmany-evadhikaras te ma phalesu kadacana ma karma-phala-hetur bhur ma te sango 'stv akarmani.").hexdigest(), 16)

F.<d_h, d_l> = PolynomialRing(Zmod(n))

f = s * (int(h >> 128) * (1 << 128) + d_h) - (h + r * (d_l + d_h * (1 << 128)))

M = list(f.coefficients())

M = block_matrix(ZZ, [
    [matrix(M).T, 1], 
    [n, 0]
])

w = diagonal_matrix([1, 1 << 128, 1 << 128, 1], sparse=0)

M /= w
M = M.BKZ()
M *= w

for i in M:
    if i[0] == 0 and abs(i[-1]) == 1:
        d_h = abs(i[1])
        d_l = abs(i[2])
        break


d = d_l + d_h * (1 << 128)
flag = sha256(str(d).encode()).hexdigest()
print(f"bi0sCTF{{{flag}}}")
```

#### 5. Baby isogeny

```py
#!/usr/bin/env sage
import os, sys, hashlib
from Crypto.Cipher import AES

e2, e3 = 216, 137
p = 2**e2 * 3**e3 - 1
F.<i> = GF(p**2, modulus=x^2+1)
E0 = EllipticCurve(F, [0,6,0,1,0])

def generate_torsion_basis(E, l, e, cofactor):
    while True:
        P = cofactor * E.random_point()
        if (l^(e-1)) * P != 0: 
            break
    while True:
        Q = cofactor * E.random_point()
        if (l^(e-1)) * Q != 0 and P.weil_pairing(Q, l^e) != 1:
            break
    return P, Q

P2, Q2 = generate_torsion_basis(E0, 2, e2, 3^e3)
P3, Q3 = generate_torsion_basis(E0, 3, e3, 2^e2)

def comp_iso(E, Ss, ℓ, e):
    φ,  E1 = None, E
    for k in range(e):
        R = [ℓ**(e-k-1) * S for S in Ss]
        ϕk = E1.isogeny(kernel=R)
        Ss = [ϕk(S) for S in Ss]
        E1 = ϕk.codomain()
        φ  = ϕk if φ is None else ϕk * φ
    return φ, E1

def j_ex(E, sk, pk, ℓ, e):
    φ, _ = comp_iso(E, [pk[0] + sk*pk[1]], ℓ, e)
    return φ.codomain().j_invariant()

def aes_cbc_encrypt(key, pt):
    iv = os.urandom(16)
    c  = AES.new(hashlib.sha256(key).digest()[:16], AES.MODE_CBC, iv)
    return iv, c.encrypt(pt)

def recv_K_elem(prompt):
    print(prompt)
    re = ZZ(input("  re: "))
    im = ZZ(input("  im: "))
    return F(re + i*im)

supersingular_cache = set()
def is_supersingular(Ei):
    a = Ei.a_invariants()
    if a in supersingular_cache:
        return True
    result = Ei.is_supersingular(proof=False)
    if result:
        supersingular_cache.add(a)
    return result

def recv():
    print("input your public key:")
    a1 = recv_K_elem("a1: ")
    a2 = recv_K_elem("a2: ")
    a3 = recv_K_elem("a3: ")
    a4 = recv_K_elem("a4: ")
    a6 = recv_K_elem("a6: ")
    Ei = EllipticCurve(F, [a1,a2,a3,a4,a6])
    assert(is_supersingular(Ei))
    Px = recv_K_elem("Px: ")
    Py = recv_K_elem("Py: ")
    P = Ei(Px, Py)
    Qx = recv_K_elem("Qx: ")
    Qy = recv_K_elem("Qy: ")
    Q = Ei(Qx, Qy)
    assert(P*(3^e3) == Ei(0) and P*(3^(e3-1)) != Ei(0))
    assert(Q*(3^e3) == Ei(0) and Q*(3^(e3-1)) != Ei(0))
    assert(P.weil_pairing(Q, 3^e3) == (P3.weil_pairing(Q3, 3^e3))^(2^e2))
    return (Ei, P, Q)

kA = randint(1,2**e2-1)
φA, EA = comp_iso(E0, [P2 + kA*Q2], 2, e2)
φAPB = φA(P3)
φAQB = φA(Q3)
φAPA = φA(P2) 
φAQA = φA(Q2)

j1 = j_ex(E0, kA, (P3,Q3), 3, e3)
flag1 = open('flag1.txt','rb').read().rjust(16,b'\x00')
iv1, ct1 = aes_cbc_encrypt(str(j1).encode(), flag1)

kB = randint(1, 3^e3 - 1)
φB, EB = comp_iso(E0, [P3 + kB*Q3], 3, e3)
φBPA = φB(P2)
φBQA = φB(Q2)

j2 = j_ex(E0, kB, (P2,Q2), 2, e2)
flag2 = open('flag2.txt','rb').read().rjust(16,b'\x00')
iv2, ct2 = aes_cbc_encrypt(str(j2).encode(), flag2)

print("\n=== public key ===")
print("PA:", P2.xy())
print("QA:", Q2.xy())
print("PB:", P3.xy())
print("QB:", Q3.xy())
print("EA invariants:", EA.a_invariants())
print("φAPB:", φAPB.xy())
print("φAQB:", φAQB.xy())
print("φAPA:", φAPA.xy())
print("φAQA:", φAQA.xy())
print("EB invariants:", EB.a_invariants())
print("φBPA:", φBPA.xy())
print("φBQA:", φBQA.xy())
print("IV1:", iv1.hex())
print("CT1:", ct1.hex())
print("IV2:", iv2.hex())
print("CT2:", ct2.hex())

print("\nNow you may submit your flag")
for _ in range(300):
    try:
        pk2 = recv()
        Ei, P, Q = pk2
        iv = bytes.fromhex(input("IV? ").strip())
        ct = bytes.fromhex(input("CT? ").strip())
        j  = j_ex(Ei, kB, (P,Q), 3, e3)
        key= hashlib.sha256(str(j).encode()).digest()[:16]
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        print("Good!" if pt == flag1 else "Bad!")
    except:
        print("Error!") ; sys.exit(1)
```

đây là một chall về SIDH, một mật mã yếu và đã có code để tấn công rồi nên chỉ cần copy code là có flag.

```py

import public_values_aux
from public_values_aux import *

load('castryck_decru_shortcut.sage')
load('sandwich_attack.sage')

import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
from Crypto.Cipher import AES

io = process(["sage", "chall.sage"])
# io = remote("13.233.255.238", 4004)
# io.interactive()
e2, e3 = 216, 137
a, b = 216, 137
p = 2**e2 * 3**e3 - 1
F = GF(p**2, modulus=[1,0,1], name = "i")
i = F.gen()

def generate_torsion_basis(E, l, e, cofactor):
    while True:
        P = cofactor * E.random_point()
        if (l^(e-1)) * P != 0: 
            break
    while True:
        Q = cofactor * E.random_point()
        if (l^(e-1)) * Q != 0 and P.weil_pairing(Q, l^e) != 1:
            break
    return P, Q

def comp_iso(E, Ss, l, e):
    φ,  E1 = None, E
    for k in range(e):
        R = [l**(e-k-1) * S for S in Ss]
        ϕk = E1.isogeny(kernel=R)
        Ss = [ϕk(S) for S in Ss]
        E1 = ϕk.codomain()
        φ  = ϕk if φ is None else ϕk * φ
    return φ, E1

def j_ex(E, sk, pk, l, e):
    φ, _ = comp_iso(E, [pk[0] + sk*pk[1]], l, e)
    return φ.codomain().j_invariant()

def decrypt_flag(iv :str, ct: str, ss: bytes):
    iv = bytes.fromhex(iv)
    ct = bytes.fromhex(ct)
    key = hashlib.sha256(ss).digest()[:16]
    c  = AES.new(key, AES.MODE_CBC, iv)
    return c.decrypt(ct)

io.recvuntil(b"PA: ")
PA = eval(io.recvline())
io.recvuntil(b"QA: ")
QA = eval(io.recvline())
io.recvuntil(b"PB: ")
PB = eval(io.recvline())
io.recvuntil(b"QB: ")
QB = eval(io.recvline())
io.recvuntil(b"EA invariants: ")
EA_invariants = eval(io.recvline())
io.recvuntil(b"APB: ")
φAPB = eval(io.recvline())
io.recvuntil(b"AQB: ")
φAQB = eval(io.recvline())
io.recvuntil(b"APA: ")
φAPA = eval(io.recvline())
io.recvuntil(b"AQA: ")
φAQA = eval(io.recvline())
io.recvuntil(b"EB invariants: ")
EB_invariants = eval(io.recvline())
io.recvuntil(b"BPA: ")
φBPA = eval(io.recvline())
io.recvuntil(b"BQA: ")
φBQA = eval(io.recvline())

io.recvuntil(b"IV1: ")
iv1 = str(io.recvline()).replace("b'", "")[:-3]
io.recvuntil(b"CT1: ")
ct1 = str(io.recvline()).replace("b'", "")[:-3]
io.recvuntil(b"IV2: ")
iv2 = str(io.recvline()).replace("b'", "")[:-3]
io.recvuntil(b"CT2: ")
ct2 = str(io.recvline()).replace("b'", "")[:-3]
print(f"{iv1 = }")
print(f"{ct1 = }")
print(f"{iv2 = }")
print(f"{ct2 = }")

E0 = EllipticCurve(F, [0,6,0,1,0])
EA = EllipticCurve(F, EA_invariants)
EB = EllipticCurve(F, EB_invariants)

PA = E0(PA)
P3 = E0(PB)
QA = E0(QA)
Q3 = E0(QB)

φAPB = EA(φAPB)
φAQB = EA(φAQB)
φAPA = EA(φAPA)
φAQA = EA(φAQA)

φBPA = EB(φBPA)
φBQA = EB(φBQA)

two_i = generate_distortion_map(E0)
recovered_key = CastryckDecruAttack(E0, PA, QA, EB, φBPA, φBQA, two_i)
j2 = j_ex(E0, recovered_key, (PA,QA), 2, e2)
print(decrypt_flag(iv2, ct2, str(j2).encode()))
```

Ngoài ra ta cũng có thể làm theo hướng ban đầu là key reused attack.

#### 6. Like PRNGS

```py
from tinyec.ec import SubGroup, Curve
from RMT import R_MT19937_32bit as special_random
from decor import HP, death_message, menu_box, title_drop
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits
from hashlib import sha256
from json import loads
import sys
import os
# from secret import FLAG
FLAG = b"KCSC{________________________}"

CORE = 0xb4587f9bd72e39c54d77b252f96890f2347ceff5cb6231dfaadb94336df08dfd


class _1000_THR_Signing_System:
    def __init__(self):
        # secp256k1 
        self.p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        self.a = 0x0000000000000000000000000000000000000000000000000000000000000000
        self.b = 0x0000000000000000000000000000000000000000000000000000000000000007
        self.Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        self.Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        self.n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        self.h = 0x1

        subgroup = SubGroup(self.p, (self.Gx, self.Gy), self.n, self.h)
        self.curve = Curve(self.a, self.b, subgroup, name="CustomCurve")

        self.cinit = 0
        self.d = self.privkey_gen()
        self.P = self.curve.g
        self.Q = self.d * self.P

        self.Max_Sec = special_random(1234567890)

    def sec_real_bits(self,bits: int) -> int:
        if bits % 32 != 0:
            raise ValueError("Bit length must be a multiple of 32")   
        exp = bits // 32
        x = self.Max_Sec.get_num() ** exp
        cyc_exhausted = 0
        while x.bit_length() != bits:
            x = self.Max_Sec.get_num() ** exp
            cyc_exhausted += 1
        return (x, cyc_exhausted)  
    
    @staticmethod
    def real_bits(bits) -> int:
        x = getrandbits(bits)
        while x.bit_length() != bits:
            x = getrandbits(bits)
        return x

    @staticmethod
    def supreme_RNG(seed: int, length: int = 10):
        while True:
            str_seed = str(seed) if len(str(seed)) % 2 == 0 else '0' + str(seed)
            sqn = str(seed**2)
            mid = len(str_seed) >> 1
            start = (len(sqn) >> 1) - mid
            end = (len(sqn) >> 1) + mid   
            yield sqn[start : end].zfill(length)
            seed = int(sqn[start : end])  
    
    def restart_level(self):
        print("S T A R T I N G  R O U T I N E . . .\n")

        self.Max_Sec = special_random(getrandbits(32))

        self.d = self.privkey_gen()
        self.P = self.curve.g
        self.Q = self.d * self.P

    def sign(self, msg: bytes) -> tuple:
        k, n1, n2, cycles = self.full_noncense_gen() # 全くナンセンスですが、日本語では
        
        kG = k * self.P
        r = kG.x % self.n
        k = k % self.n
        Hmsg = sha256()
        Hmsg.update(msg)

        s = ((b2l(Hmsg.digest()) + r * self.d) * pow(k, -1, self.n)) % self.n

        return (r, s, n1, n2, cycles)
    
    def partial_noncense_gen(self,bits: int, sub_bits: int, shift: int) -> int:
        term = self.real_bits(bits)
        _and = self.real_bits(bits - sub_bits)
        equation = term ^ ((term << shift) & _and) 
        return (term,_and,equation)


    def full_noncense_gen(self) -> tuple:
        k_m1 = self.real_bits(24)
        k_m2 = self.real_bits(24) 
        k_m3 = self.real_bits(69) 
        k_m4 = self.real_bits(30) 

        k_, cycle_1 = self.sec_real_bits(32)
        _k, cycle_2 = self.sec_real_bits(32)

        benjamin1, and1, eq1 = self.partial_noncense_gen(32, 16, 16)
        benjamin2, and2, eq2 = self.partial_noncense_gen(32 ,16 ,16)

        const_list = [k_m1, (benjamin1 >> 24 & 0xFF), k_m2, (benjamin1 >> 16 & 0xFF) , k_, (benjamin1 >> 8 & 0xFF), k_m3, (benjamin1 & 0xFF), k_m4, (benjamin2 >> 24 & 0xFFF), _k]
        shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]

        n1 = [and1, eq1]
        n2 = [and2, eq2]
        cycles = [cycle_1, cycle_2]

        noncense = 0
        for const, shift in zip(const_list, shift_list):
            noncense += const << shift
        return noncense, n1, n2, cycles   


    def privkey_gen(self) -> int:
        simple_lcg = lambda x: (x * 0xeccd4f4fea74c2b057dafe9c201bae658da461af44b5f04dd6470818429e043d + 0x8aaf15) % self.n

        if not self.cinit:
            RNG_seed = simple_lcg(CORE)
            self.n_gen = self.supreme_RNG(RNG_seed)
            RNG_gen = next(self.n_gen)
            self.cinit += 1
        else:
            RNG_gen = next(self.n_gen)               

        p1 = hex(self.real_bits(108))
        p2 = hex(self.real_bits(107))[2:]

        priv_key = p1 + RNG_gen[:5] + p2 + RNG_gen[5:]

        return int(priv_key, 16)
    
    def gen_encrypted_flag(self) -> tuple:
        sha2 = sha256()
        sha2.update(str(self.d).encode('ascii'))
        key = sha2.digest()[:16]
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(FLAG, 16))
        return (ciphertext.hex(), iv.hex())
            
    def _dead_coin_params(self) -> tuple:
        base = 2
        speed = getrandbits(128)
        feedbacker_parry = int(next(self.n_gen))
        style_bonus = feedbacker_parry ^ (feedbacker_parry >> 5)
        power = pow(base, style_bonus, speed)
        return (power, speed, feedbacker_parry)
    
    def deadcoin_verification(self, tries):

        if tries < 3:
            print(f"Successfully perform a {"\33[33m"}deadcoin{"\33[0m"} and perform a {"\33[34m"}feedbacker{"\33[0m"} parry for getting {"\33[1;91m"}BLOOD{"\33[0m"} to survive.\n")
            power, speed, feedbacker_parry = self._dead_coin_params()
            print(f"Calculated power and speed for the number - {tries+1} deadcoin: {power, speed}")
            try:
                action_code = int(input("Action code: "))
                if action_code == feedbacker_parry:
                    blood = self.Max_Sec.get_num()
                    print(f"[+ FISTFUL OF DOLLAR]")
                    print(f"Here's some {"\33[1;91m"}BLOOD{"\33[0m"} - ID: {blood}")
                    return True
                else:
                    print("Missed.")
            except:
                print("Invalid action code")
        else:
            print("You're done.")
        return False


class _1000_THR_EARTHMOVER:
    def __init__(self):
        self.Boss = _1000_THR_Signing_System()

    def get_encrypted_flag(self):
        ciphertext, iv = self.Boss.gen_encrypted_flag()   
        return {"ciphertext": ciphertext,"iv": iv}      
    
    def perform_deadcoin(self, tries):
        return self.Boss.deadcoin_verification(tries)

    def call_the_signer(self):
        msg = input("What do you wish to speak? ").encode()
        r, s, n1, n2, cycles = self.Boss.sign(msg)
        return {"r": r, "s": s, "nonce_gen_consts": [n1, n2], "heat_gen": cycles}

    def level_restart(self):
        self.Boss.restart_level()
    
    def level_quit(self):
        sys.exit()
    
   
def main():
    from time import sleep
    LEVEL = _1000_THR_EARTHMOVER()
    tries = 0
    title_drop()


    V1 = HP(100,100, "V1", HP.color_red)

    while True:
        try:
            menu_box()
            print(f'\n{V1}')
            move = loads(input("\nExpecting Routine in JSON format: "))

            if "event" not in move:
                print({"Error": "Unrecognised event"})
                continue

            v1_action = move["event"]

            survive = V1.check(v1_action)
            if not survive:
                death_message()
                break

            if v1_action == "get_encrypted_flag":
                print(LEVEL.get_encrypted_flag())
                V1.update(V1.current_health-50)

            elif v1_action == "perform_deadcoin":
                verify = LEVEL.perform_deadcoin(tries)
                tries += 1
                if verify:
                    V1.update(V1.current_health+20)

            elif v1_action == "call_the_signer":
                print(LEVEL.call_the_signer())
                V1.update(V1.current_health-20)

            elif v1_action == "level_restart":
                LEVEL.level_restart()
                V1.update(100)

            elif v1_action == "level_quit":
                LEVEL.level_quit()

            else:
                print({"Error": "Unrecognised V1 action"})

        except Exception as e:
            print({"Error": str(e)})

        
if __name__ == "__main__":
    main()

```

đây là một bài ecdsa với key reused và vuln chính nằm ở cách tạo k như sau:

```py
    def full_noncense_gen(self) -> tuple:
        k_m1 = self.real_bits(24)
        k_m2 = self.real_bits(24) 
        k_m3 = self.real_bits(69) 
        k_m4 = self.real_bits(30) 

        k_, cycle_1 = self.sec_real_bits(32)
        _k, cycle_2 = self.sec_real_bits(32)

        benjamin1, and1, eq1 = self.partial_noncense_gen(32, 16, 16)
        benjamin2, and2, eq2 = self.partial_noncense_gen(32 ,16 ,16)

        const_list = [k_m1, (benjamin1 >> 24 & 0xFF), k_m2, (benjamin1 >> 16 & 0xFF) , k_, (benjamin1 >> 8 & 0xFF), k_m3, (benjamin1 & 0xFF), k_m4, (benjamin2 >> 24 & 0xFFF), _k]
        shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]

        n1 = [and1, eq1]
        n2 = [and2, eq2]
        cycles = [cycle_1, cycle_2]

        noncense = 0
        for const, shift in zip(const_list, shift_list):
            noncense += const << shift
        return noncense, n1, n2, cycles 
```


dễ thấy k được tạo từ nhiều phần ghép lại trong đó ta có thể biết được một vài phần như benjamin và `_k`, `k_` bằng cách attack hàm random (sau một thời gian tìm thì mình có tìm được tool attack bằng z3 chỉ với 3 output). Khi có được các thông tin cần thiết thì code solve linear sẽ giải quyết phần còn lại và dễ dàng có được flag.

```py

import os
os.environ["TERM"] = "linux"

from pwn import *
from Crypto.Util.number import *
from z3 import *
import json
from tinyec.ec import SubGroup, Curve
from RMT import R_MT19937_32bit as special_random
from decor import HP, death_message, menu_box, title_drop
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits
from hashlib import sha256
from json import loads
import sys
from tqdm import *

s = connect("13.233.255.238", 4002)
# s = process(["python3", 'chall.py'])
# s.interactive()

def supreme_RNG(seed: int, length: int = 10):
    while True:
        str_seed = str(seed) if len(str(seed)) % 2 == 0 else '0' + str(seed)
        sqn = str(seed**2)
        mid = len(str_seed) >> 1
        start = (len(sqn) >> 1) - mid
        end = (len(sqn) >> 1) + mid   
        yield sqn[start : end].zfill(length)
        seed = int(sqn[start : end]) 

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
h = 0x1
simple_lcg = lambda x: (x * 0xeccd4f4fea74c2b057dafe9c201bae658da461af44b5f04dd6470818429e043d + 0x8aaf15) % n
CORE = 0xb4587f9bd72e39c54d77b252f96890f2347ceff5cb6231dfaadb94336df08dfd
RNG_seed = simple_lcg(CORE)
n_gen = supreme_RNG(RNG_seed)
RNG_gen = next(n_gen)

def call_the_signer():
    s.recvuntil(b"Expecting Routine in JSON format: ")
    s.sendline(json.dumps({
        "event": "call_the_signer"
    }))
    s.sendline(b"0")
    Hmsg = sha256()
    Hmsg.update(b"0")
    s.recvuntil(b"What do you wish to speak? ")
    tmp = eval(s.recvline().strip())
    tmp["h"] = bytes_to_long(Hmsg.digest())
    return tmp

def perform_deadcoin():
    s.recvuntil(b"Expecting Routine in JSON format: ")
    s.sendline(json.dumps({
        "event": "perform_deadcoin"
    }))
    s.recvuntil(b": ")
    power, speed  = eval(s.recvline())

    feedbacker_parry = int(next(n_gen))
    style_bonus = feedbacker_parry ^ (feedbacker_parry >> 5)
    if power == pow(2, style_bonus, speed):
        s.sendline(str(feedbacker_parry).encode())
    s.recvuntil(b"ID: ")
    return int(s.recvline().strip().decode())

def get_encrypted_flag():
    s.recvuntil(b"Expecting Routine in JSON format: ")
    s.sendline(json.dumps({
        "event": "get_encrypted_flag"
    }))

    tmp = eval(s.recvline())
    return tmp

enc = (get_encrypted_flag())

from gf2bv import LinearSystem
def t(_and, eq):
    lin = LinearSystem([32])
    term = lin.gens()[0]
    zeros = [int(eq) ^ (term ^ ((term << 16) & int(_and)))]
    sol = lin.solve_one(zeros)
    print(int(eq) ^ (int(sol[0]) ^ ((int(sol[0]) << 16) & int(_and))))
    return sol[0]

def find_benjamin(c):
    return [t(*c[0]), t(*c[1])]

sig = []

from test_mersenne import *
from solve_linear import solve_linear_mod
for i in range(3):
    sig.append((i, perform_deadcoin()))

seed = test_seed_mt(sig)
Max_Sec = special_random(seed)
Max_Sec.get_num()
Max_Sec.get_num()
Max_Sec.get_num()
print(f"Seed: {seed}")

def sec_real_bits(bits: int) -> int:
    if bits % 32 != 0:
        raise ValueError("Bit length must be a multiple of 32")   
    exp = bits // 32
    x = Max_Sec.get_num() ** exp
    cyc_exhausted = 0
    while x.bit_length() != bits:
        x = Max_Sec.get_num() ** exp
        cyc_exhausted += 1
    return x

k_m1 = [var(f"m1_{_}") for _ in range(5)]
k_m2 = [var(f"m2_{_}") for _ in range(5)]
k_m3 = [var(f"m3_{_}") for _ in range(5)]
k_m4 = [var(f"m4_{_}") for _ in range(5)]

bound = {}
for i in range(5):
    bound[k_m1[i]] = (0, 1 << 24)
    bound[k_m2[i]] = (0, 1 << 24)
    bound[k_m3[i]] = (0, 1 << 69)
    bound[k_m4[i]] = (0, 1 << 30)

n_ = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
eqs = []

sig = (call_the_signer())
c = sig["nonce_gen_consts"]
benjamin1_, benjamin2_ = find_benjamin(c)
k_m5_ = sec_real_bits(32)
k_m6_ = sec_real_bits(32)
i = 0
const_list = [k_m1[i], (benjamin1_ >> 24 & 0xFF), k_m2[i], (benjamin1_ >> 16 & 0xFF) , k_m5_, (benjamin1_ >> 8 & 0xFF), k_m3[i], (benjamin1_ & 0xFF), k_m4[i], (benjamin2_ >> 24 & 0xFFF), k_m6_]
shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]
noncense = 0
for const, shift in zip(const_list, shift_list):
    noncense += const * (1 << shift)
k1 = noncense
r1_, s1_, h1_ = sig["r"], sig["s"], sig["h"]

for i in range(1, 5):
    k_m5 = sec_real_bits(32)
    k_m6 = sec_real_bits(32)
    sig = (call_the_signer())
    c = sig["nonce_gen_consts"]
    benjamin1, benjamin2 = find_benjamin(c)
    const_list = [k_m1[i], (benjamin1 >> 24 & 0xFF), k_m2[i], (benjamin1 >> 16 & 0xFF) , k_m5, (benjamin1 >> 8 & 0xFF), k_m3[i], (benjamin1 & 0xFF), k_m4[i], (benjamin2 >> 24 & 0xFFF), k_m6]
    shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]
    noncense = 0
    for const, shift in zip(const_list, shift_list):
        noncense += const * (1 << shift)
    r_, s_, h_ = sig["r"], sig["s"], sig["h"]

    eqs.append([r_ * k1 * s1_ - r1_ * noncense * s_ == r_ * h1_ - r1_ * h_, n_])

tmp = (solve_linear_mod(eqs, bound))
print(tmp)
i = 0
const_list = [tmp[k_m1[i]], (benjamin1_ >> 24 & 0xFF), tmp[k_m2[i]], (benjamin1_ >> 16 & 0xFF) , k_m5_, (benjamin1_ >> 8 & 0xFF), tmp[k_m3[i]], (benjamin1_ & 0xFF), tmp[k_m4[i]], (benjamin2_ >> 24 & 0xFFF), k_m6_]
shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]
noncense = 0
for const, shift in zip(const_list, shift_list):
    noncense += const * (1 << shift)

n_ = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
d = ((s1_ * noncense - h1_) * pow(r1_, -1, n_)) % n_

enc_flag = enc["ciphertext"]
iv = bytes.fromhex(enc["iv"])
enc_flag = bytes.fromhex(enc_flag)

sha2 = sha256()
sha2.update(str(d).encode('ascii'))
key = sha2.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
print(cipher.decrypt(enc_flag))
```