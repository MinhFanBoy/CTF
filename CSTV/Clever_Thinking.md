
### ELIPTIC

---

**_TASK:_**

I think that Diffie-Hellman is better with some curves, maybe elliptic ones. Let's share a secret!

Wrap the secret (which is a point) in uoftctf{(x:y:z)}, where (x:y:z) are homogeneous coordinates.


```
m = 235322474717419
F = GF(m)
C = EllipticCurve(F, [0, 8856682])

public_base = (185328074730054:87402695517612:1)

Q1 = (184640716867876:45877854358580:1) # my public key
Q2 = (157967230203538:128158547239620:1) # your public key

secret = ...
my_private_key = ...
assert(my_private_key*public_base == Q1)
assert(my_private_key*Q2 == secret)
```

---

```sage

m = 235322474717419
F = GF(m)
C = EllipticCurve(F, [0, 8856682])

print(C)

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)



public_base = C(185328074730054,87402695517612)

Q1 = C(184640716867876,45877854358580) # my public key
Q2 = C(157967230203538,128158547239620) # your public key

n = SmartAttack(Q1, public_base , m)

print(n)
print()

#secret = ...
#my_private_key = ...
#assert(my_private_key*public_base == Q1)
#assert(my_private_key*Q2 == secret)



```

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

a = 0
b = 8856682
m = 235322474717419

q = (157967230203538,128158547239620)
n = 42088443624734



print(multiplitcation(q, a, b, m, n))


```


