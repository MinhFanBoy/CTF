
### Eliptic


---

**_TASK:_**

We will work with the following elliptic curve, and prime:

$$E: Y^2 = X^3 + 497 * X + 1768,\quad p: 9739$$

You can test your algorithm by asserting: $X + Y = (1024, 4440)$ and $X + X = (7284, 2107)$ for $X = (5274, 2841)$ and $Y = (8669, 740)$.


Using the above curve, and the points $P = (493, 5564), Q = (1539, 4742), R = (4403,5202)$, find the point $S(x,y) = P + P + Q + R$ by implementing the above algorithm.

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
    
a = 497
b = 1768
n = 9739

P = (493, 5564)
Q = (1539, 4742)
R = (4403,5202)

print(add_point(add_point(P, P, a, b, n), add_point(Q, R, a, b, n), a, b, n))


```
