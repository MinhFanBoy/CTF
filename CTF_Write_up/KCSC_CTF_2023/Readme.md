
### KCSC_CTF_2023

#### 1. CFB64

**__chal.py__**

```py
import time
import sys
import os
from Crypto.Cipher import AES
from flag import flag

key = os.urandom(16)
iv = os.urandom(16)

def encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=64)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

print(f'encrypted_flag = {encrypt(key, iv, flag).hex()}')

for _ in range(23):
    plaintext = bytes.fromhex(input("plaintext: "))
    print(f'ciphertext = {encrypt(key, iv, plaintext).hex()}')

```

![alt text](CFB_encryption.svg.png)

flag được mã hóa bằng AES mode CFB, nó mã hóa lần lượt từng 8 bytes của flag. 

có c = xor(AES(IV), plaintext)

với:

+ c1 = xor(AES(IV), flag)
+ c2 = xor(AES(IV), p1)

thì ta có thể dễ dàng tìm lại flag = xor(c1, c2, p1) và tương tự cho các phần tiếp theo là ta có thể dễ dàng tìm được flag.

```py

from pwn import *

s = process(["python", "chall.py"])
flag = b""

enc_flag = s.recvline().split(b" = ")[1].strip().decode()
enc_flag = bytes.fromhex(enc_flag)
enc_flag = [enc_flag[i:i+8] for i in range(0, len(enc_flag), 8)]

for i in enc_flag:
    s.sendline((flag + i).hex().encode())
    enc = s.recvline().split(b" = ")[1].strip().decode()
    enc = bytes.fromhex(enc)[-8:]
    flag += enc

print(flag)

```

#### 2. Only Lord Can Go

**__chal.py__**

```go
package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
)

func main() {
    fmt.Println(" _  __  ___  ___   ___   _      ___   _____  _____  ___  ___ __  __ ")
    fmt.Println("| |/ / / __|/ __| / __| | |    / _ \\ |_   _||_   _|| __|| _ \\\\ \\ / / ")
    fmt.Println("| ' < | (__ \\__ \\| (__  | |__ | (_) |  | |    | |  | _| |   / \\ V /  ")
    fmt.Println("|_|\\_\\ \\___||___/ \\___| |____| \\___/   |_|    |_|  |___||_|_\\  |_|   ")
	fmt.Println()
	
	var a,b,c,d,e,y,m int
	m = 1<<31 - 1
	a = rand.Intn(m)
	b = rand.Intn(m)
	c = rand.Intn(m)
	d = rand.Intn(m)
	e = rand.Intn(m)
	y = rand.Intn(m)

	fmt.Println("I will give u 5 lucky numbers :>")
	for i:=1; i<=5; i++ {
		y = (a*d + b*e + c) % m
		fmt.Printf("Lucky number %v: %v \n", i, y)
		e = d
		d = y
	}
	fmt.Println()

	fmt.Println("Now show off your guessing skills, ego ._.")
	var guess string
	for i:=1; i<=23; i++ {
		y = (a*d + b*e + c) % m
		fmt.Print("Guess: ")
		fmt.Scan(&guess)
		numGuess, _ := strconv.Atoi(guess)
		if numGuess == y {
			fmt.Printf("Nai xuw !!! Remain: %v/23\n", 23-i)
		} else {
			fmt.Println("Luck is only for those who try, if you don't understand that, then get out !!!")
			return
		}
		e = d
		d = y
	}

	fmt.Println("WOW, I rly want how do u can guess all correctly, plz sharing w me :<")
	content, _ := ioutil.ReadFile("flag.txt")
	fmt.Println(string(content))
}

```

Ta có kết quả của hàm sau và cần phải trả lời đúng giá trị của các `y` tiếp theo.

```golang
	for i:=1; i<=5; i++ {
		y = (a*d + b*e + c) % m
		fmt.Printf("Lucky number %v: %v \n", i, y)
		e = d
		d = y
    }
```
do có 5 ẩn và có 5 phương trình nên ta có thể dùng groeber basis để tìm lại nghiệm. Khi đã biết các ẩn rồi thì ta có thể dễ dàng tìm được các y tiếp theo và có được flag.


```py
import os
os.environ["TERM"] = "linux"
from pwn import *
loglevel = 'debug'
context.log_level = loglevel

import random
m = (1<<31) - 1

s = process(["go", "run", "main.go"])

o = []

for i in range(1, 6):
    s.recvuntil(f"Lucky number {i}: ")
    o.append(int(s.recvuntil(b"\n").decode().strip()))

def cacl(o):
    F.<a, b, c, d, e> = PolynomialRing(Zmod(m))

    k = []
    for i in range(5):
        y = (a*d + b*e + c)
        k.append(y)
        e = d
        d = y

    eq = []
    for _ in zip(k, o):
        eq.append(_[0] - _[1])
        

    I = ideal(eq)
    i = I.groebner_basis()

    if len(i) == 5:
        c_a = (-i[0].coefficients()[1]) % m
        c_b = (-i[1].coefficients()[1]) % m
        c_c = (-i[2].coefficients()[1]) % m
        c_d = (-i[3].coefficients()[1]) % m
        c_e = (-i[4].coefficients()[1]) % m
        print("a, b, c, d, e", c_a, c_b, c_c, c_d, c_e)
        return c_a, c_b, c_c, c_d, c_e
    return None

tmp = cacl(o)

if tmp:
    c_a, c_b, c_c, c_d, c_e = tmp
else:
    print("Error: Unable to calculate coefficients")
    exit(1)
    
for i in range(5):
    c_y = (c_a*c_d + c_b*c_e + c_c) % m
    c_e = c_d
    c_d = c_y
    
for i in range(23):
    c_y = (c_a*c_d + c_b*c_e + c_c) % m
    s.sendline(str(c_y).encode())
    c_e = c_d
    c_d = c_y

s.interactive()
```

#### 3. ECDSAAAA

```java
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        try {
            KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println(publicKey);

            System.out.println("############################################# SIGN #############################################");
            Scanner sc = new Scanner(System.in);
            System.out.print("Enter msg: ");
            String msg = sc.nextLine();
            if (msg.equals("Hi im Gan Dam")) {
                System.out.println("Go to airport :<");
                System.exit(0);
            }
            String base64Ssignature = sign(msg, privateKey);
            System.out.printf("Signature: %s \n", base64Ssignature);

            System.out.println("############################################# VERIFY #############################################");
            System.out.print("Enter msg: ");
            String msgV = sc.nextLine();
            System.out.print("Enter signature: ");
            String signV = sc.nextLine();
            if (verify(msgV, signV, publicKey)) {
                if (msgV.equals("Hi im Gan Dam")) {
                    System.out.println("KCSC{_______________}");
                } else {
                    System.out.println("Go to airport :<");
                    System.exit(0);
                }
            } else {
                System.out.println("Go to airport :<");
                System.exit(0);
            }
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }

    public static String sign(String msg, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA512withECDSAinP1363Format");
        signature.initSign(privateKey);
        signature.update(msg.getBytes("UTF-8"));
        String base64Ssignature = Base64.getEncoder().encodeToString(signature.sign());
        return base64Ssignature;
    }

    public static boolean verify(String msg, String base64Ssignature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA512withECDSAinP1363Format");
        verifier.initVerify(publicKey);
        verifier.update(msg.getBytes("UTF-8"));
        byte[] signature = Base64.getDecoder().decode(base64Ssignature);
        return verifier.verify(signature);
    }
}
```

Bài này có liên quan tới `CVE-2022-21449`, cụ thể hơn thì đây là lỗi khiến cho hàm với r = 0, s = 0  thì nó vẫn có thể vượt qua được hàm verify. Nên trong bài này mình chỉ cần gửi bytes 0 là có thể dễ dàng có được flag.

#### 4. CRC64

**__chal.py__**

```py
import secrets
import time
import sys
import os

from flag import flag

key = secrets.randbits(64)

def crc64(data: bytes, init: int) -> int:
    g = 0xcd8da4ff37e45ec3
    crc = init

    for x in data:
        crc = crc ^ x
        for _ in range(8):
            crc = ((crc >> 1) ^ (g * (crc & 1))) & 0xffffffffffffffff
    return crc


def auth(code: int, t: int) -> bool:
    return crc64((key ^ t).to_bytes(8, "little"), code) == code

while True:
    print("[A]uthenticate yourself")
    print("[H]int for pre-shared key")
    choice = input("> ").strip()
    if choice == "A":
        code = int(input("code: "), 16)
        assert 0 <= code < 2**64

        # key is changed in every 5 seconds
        t = int(time.time()) // 5 * 5
        if auth(code, t):
            print(flag)
            sys.exit(0)
        print("WRONG code")

    elif choice == "H":
        t = int(time.time()) // 5 * 5
        hint = crc64(b"hint", crc64((key ^ t).to_bytes(8, "little"), 0))
        print(f"hint: {hint:x}")

    else:
        sys.exit(0)
```

Một hàm CRC có thể được viết lại như sau:

+ $CRC(M) = M * x^n + Y + (Y + I) * x^b + Z \pmod{poly}$

trong đó:

+ poly là đa thức của giá trị g trong trường này.
+ n là độ dài output của hàm.
+ FF là giá trị cơ bản tương đương với 2^n - 1
+ b là độ dài bit của msg.
+ M là msg được mã hóa.
+ I là giá trị init của hàm và được xor với FF
+ Z là giá trị out của hàm và được xor với FF
+ Y = FF
+ do ta đang thực hiện tính toán trên bit nên các bit phải được đảo lại.

Ta cso thể viết lại hàm CRC64 của bài này như sau:

+ $CRC64(M) = M * x^{64} + Y + (Y + I) * x^b \pmod{g}$

Trong bài ta có thể có giá trị hint như sau:

+ `hint = crc64(b"hint", crc64((key ^ t).to_bytes(8, "little"), 0))`

coi `k = crc64((key ^ t).to_bytes(8, "little"), 0)`

thì bây giờ ta cần phải tìm lại k sao cho `hint = crc64(b"hint", k)`

sử dụng công thức ở trên ta có:

$$
hint = {"hint"} * x^{64} + FF + (FF + (k \oplus FF)) * x^{8 * 4} \pmod{g}
$$

do ta đã biết tất cả các giá trị nên có thể dễ dàng tìm lại k. 

khi đó `k = crc64(key ^ t, 0)` đưa về công thức tương tự ta có.

$$
k = (key \oplus t) * x^{64} + FF + (FF + (0 \oplus FF)) * x^b \pmod{g}
$$

và từ đó có thể tìm lại key.

khi có key rồi thì ta cần phải tìm giá trị `code` sao cho thỏa mãn `crc64((key ^ t).to_bytes(8, "little"), code) == code`

${code}= (key \oplus t) * x^{64} + FF + (FF + ({code} \oplus FF)) * x^b \pmod{g}$

do cũng chỉ có 1 ẩn nên ta có thể dễ dàng tìm được giá trị có và code được flag.

```py
import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
from Crypto.Util.number import *

g = 0xcd8da4ff37e45ec3
FF = 0xffffffffffffffff
n = 64

R.<x> = GF(2)['x']

def i2p(p):
    return R(Integer(p).bits())

def p2i(p):
    return Integer(p.list(), 2)

def rev(p, n):
    p = (p.list() + [0] * n)[:n]
    return R(p[::-1])

poly = rev(i2p(g), 64) + x**64

K = GF(2**64, "x",modulus = poly)
x = K.gens()[0]

def int2poly(p, n = 64):
    p = K(Integer(p).bits())
    p = (p.list() + [0] * n)[:n]
    return K(p[::-1])

def poly2int(p, padlen=64):
    L = p.list()
    L += [0] * (padlen - len(L))
    return int(ZZ(L[::-1], base=2))

def attack(hint, data, k):
    hint = int2poly(hint)
    I = int2poly(FF ^^ k)
    Y = int2poly(FF)
    Z = int2poly(0 ^^ FF)
    b = len(data)*8
    M1 = int2poly(int.from_bytes(data, 'little'), b)

    f = hint - (M1 * x ^ n + Y + Z)
    f = (f/ (x^b)) - Y
    f = f + Y

    I2 = int2poly(FF ^^ k)
    b2 = 8 * 8
    f = (f - ((Y + I2) * x ^ b2 + Y + Z))/(x^n)

    return long_to_bytes(poly2int(f))[::-1]

def attack2(data):
    Y = int2poly(FF)
    b = len(data)*8
    M1 = int2poly(int.from_bytes(data, 'little'), b)

    I = (M1 * x ^ n - Y * x^b - Y) / (x^b + 1)
    code = poly2int(I) ^^ FF
    return code


s = process(["python3", "chall.py"])

context.log_level = "debug"
s.sendline(b"H")
s.recvuntil(b"hint: ")

hint = int(s.recvline().strip(), 16)

data = attack(hint, b"hint", 0)
code = attack2(data)

s.sendline(b"A")
s.sendline(hex(code)[2:].encode())

s.interactive()
```