from Crypto.Random import random
import numpy as np
from numpy.linalg import matrix_power

def factorial(n):
    if n == 0: return 1
    y = 1
    for i in range(1, n+1):
        y *= i
    return y

def lehmer_encode(s):
    n = len(s)
    num_factoradic = []
    remaining_indices = list(range(n))
    for x in s:
        i = remaining_indices.index(x)
        num_factoradic.append(i)
        remaining_indices.pop(i)
    num = 0
    for i, x in enumerate(num_factoradic):
        num += x * factorial(n - i - 1)
    return (num, n)

def lehmer_decode(c):
    (num, n) = c
    num_factoradic = []
    k = 0
    while factorial(k) <= num:
        k += 1
    for i in reversed(range(k)):
        x = num // factorial(i)
        num_factoradic.append(x)
        num -= x * factorial(i)
    num_factoradic = [0] * (n - k) + num_factoradic
    remaining_indices = list(range(n))
    s = []
    for x in num_factoradic:
        s.append(remaining_indices.pop(x))
    return s

def group_operation(s1, s2):
    assert(len(s1) == len(s2))
    n = len(s1)
    y = [0] * n
    for i in range(n):
        y[i] = s1[s2[i]]
    return y

def group_inv(s):
    n = len(s)
    y = [0] * n
    for i in range(n):
        y[s[i]] = i
    return y

def group_exp(s, y):
    n = len(s)
    bit_length = 0
    y0 = y
    while y0 > 0:
        y0 >>= 1
        bit_length += 1
    result = list(range(n))
    for i in reversed(range(bit_length)):
        result = group_operation(result, result)
        if (y >> i) & 1 == 1:
            result = group_operation(result, s)
    return result

def key_gen(n, q, g):
    x = random.randint(1, q-1)
    h = group_exp(g, x)
    return ((n, q, g, h), (n, q, g, x)) # public key is (n, q, g, h), secret key is (n, q, g, x)

# m is a byte string
def encrypt(pk, m):
    n, q, g, h = pk
    int_m = int.from_bytes(m, "little")
    perm_m = lehmer_decode((int_m, n))
    y = random.randint(1, q-1)
    s = group_exp(h, y)
    c1 = group_exp(g, y)
    c2 = group_operation(perm_m, s)
    return (c1, c2)

def decrypt(sk, c):
    n, q, g, x = sk
    (c1, c2) = c
    s = group_exp(c1, x)
    perm_m = group_operation(c2, group_inv(s))
    int_m, _ = lehmer_encode(perm_m)
    m = int_m.to_bytes((int_m.bit_length() + 7) // 8, "little")
    return m