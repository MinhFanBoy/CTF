
### Crypto_learn

---

**_TASK:_**

Alice has been sharing secret encrypted messages with Bob. I would really like to know what those are...

I contacted my good friend Eve, a well-known eavesdropper. She sent me the numbers she found at the beginning of their conversation. By the look of things, this looks like a key exchange. If we would find the key, we would be able to decode every message they encrypted with it!

Help me find both private keys. To submit the flag, decode them correctly and wrap them into CTFlearn{<Alice>_<Bob>} format.

Hint: the title of this challenge is a pun... I can't tell you more ;)

**_FILE:_**

      p = 0x8c5378994ef1b
      g = 0x02
      
      A = 0x269beb3b0e968
      B = 0x4757336da6f70

---

Hmm bài này làm xong mà cũng không hiểu lắm. Mình sử dụng kiến thức đã có từ các bài trước. Tính a, b bằng hàm discrete_log trên sympy là xong.

```py

from sympy.ntheory.residue_ntheory import *
from Crypto.Util.number import *

p = 0x8c5378994ef1b
g = 0x02

A = 0x269beb3b0e968
B = 0x4757336da6f70

a = discrete_log(p, A, g)
b = discrete_log(p, B, g)

secret_1 = pow(A, b, p)
secret_2 = pow(B, a, p)

print(secret_1, secret_2)
print(f"CTFlearn{long_to_bytes(a).decode()}_{long_to_bytes(b).decode()}")
```

> CTFlearn{H3ll0_Fr13nd}
