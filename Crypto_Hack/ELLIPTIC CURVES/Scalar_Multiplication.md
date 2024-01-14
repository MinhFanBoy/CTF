
### ELIPTIC

---

**_TASK:_**

We will work with the following elliptic curve, and prime:

$$E: Y2 = X3 + 497 X + 1768,\quad p: 9739$$

You can test your algorithm by asserting: $1337 * X = (1089, 6931)$ for $X = (5323, 5438)$.


Using the above curve, and the points $P = (2339, 2213)$, find the point $Q(x,y) = 7863 * P$ by implementing the above algorithm.

After calculating $Q$, substitute the coordinates into the curve. Assert that the point $Q$ is in $E(Fp)$.


---

```python



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

P = (2339, 2213)
n = 7863

print(multiplitcation(P, a, b, m, n))


```
