
### ELIPTIC

---

**_TASK:_**

$$E: Y2 = X3 + 497 X + 1768,\quad p: 9739,\quad G: (1804,5368)$$

Calculate the shared secret after Alice sends you $Q_A = (815, 3190)$, with your secret integer $n_B = 1829$.

Generate a key by calculating the SHA1 hash of the x coordinate (take the integer representation of the coordinate and cast it to a string). The flag is the hexdigest you find.****

---





```python


from hashlib import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes

def add_point(p, q, a, b, n):
    if p[1] == 0:
        return q
    elif q[1] == 0:
        return p
    elif p[0] == q[0] and p[1] == -q[1]:
        return (0, 0)
    else:
        if p[0] == q[0] and p[1] == q[1]:
            m = ((3 * (p[0] ** 2) + a) * pow(2 * p[1], -1, n) ) % n
        else:
            m = ((q[1] - p[1]) * (pow(q[0] - p[0], -1, n))) % n

        x = (m ** 2 - q[0] - p[0]) % n
        y = (m * (p[0] - x) - p[1]) % n
        return (x, y)

def multiplitcation(p, a, b, m, n):
    q = p
    r = (0, 0)

    while n > 0:
        if n % 2 == 1:
            r = add_point(r, q, a, b, m)
        q = add_point(q, q, a, b, m)
        n //= 2
    return r

a = 497
b = 1768
m = 9739
G = (1804,5368)

q = (815, 3190)
nB = 1829



hash = sha1()
hash.update(str(multiplitcation(q, a, b, m, nB)[0]).encode())
print(hash.hexdigest())



```
