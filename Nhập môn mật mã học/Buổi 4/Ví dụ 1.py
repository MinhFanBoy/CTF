n = 8

A = [1, 0, 1, 0, 0, 1, 1, 0]

def f(lst: list) -> int:
    return lst[1] ^ lst[2] ^ lst[4] ^ lst[6]

def LFSR(A):
    result = []
    for x in range(7):
        result.append(A[x + 1])
    result.append(f(A))
    return result

print(LFSR(LFSR(A)))
