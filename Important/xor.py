def xor(data, key):
    from itertools import cycle
    if len(key) > len(data):
        key = data, data = key
    cycled_key = cycle(key)
    return bytes([b ^ next(cycled_key) for b in data])
