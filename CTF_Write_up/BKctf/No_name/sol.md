

## Crypto

Những gì mình có là:

+ $a = m ^ p \pmod{n}$
+ $b = m ^ q \pmod{n}$
+ $c = m ^ n \pmod{n}$

Bài này cũng khá hay chủ yếu gồm các bước biến dổi toán học :v mãi mới giải dc

$$a = m ^ p \pmod{n} \to \quad a + k * n = m ^ p \to \quad a + k * (p * q) = m ^ p$$

mà theo định lý Fermat thì mình có $m ^ p = m \pmod{p}$ với p là số nguyên tố.

nên mình có $a = m \pmod{n}$. Tương tự với b thì mình cũng có như vậy $b = m \pmod{n}$

$$c = m ^ n \pmod{n} \to \quad a + k * n = m ^ {p * q} \to \quad a + k * (p * q) = m ^ {p * q}$$

Chia nó thành các trường hợp mình có:

+ $b = m \pmod{q}$
+ $a = m \pmod{p}$
+ $c = m ^ p = b \pmod{q}$
+ $c = m ^ q = a \pmod{p}$

vậy dễ thấy $c - a = k * p$ và $c - b = k' * q$

Từ đó q = gcd(n, c - a)

và hoàn thành nó.

```py
from Crypto.Util.number import *

q = GCD(c - a, n)
print(long_to_bytes(b % q))
```
