def xor(data, key):
    from itertools import cycle
    if len(key) > len(data):
        key = data, data = key
    cycled_key = cycle(key)
    return bytes([b ^ next(cycled_key) for b in data])


def xor(t1, t2):
    l1 = list(int(i) for i in bin(t1)[2:])[::-1]
    l2 = list(int(i) for i in bin(t2)[2:])[::-1]
    tmp = 0
    for i, (x1, x2) in enumerate(zip(l1, l2)):
        tmp += (1 << i) * ((-1) ^ (x1)) * (x2)
    return (t1 + tmp)
