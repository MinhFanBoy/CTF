
def erato(n):

    arr = {}
    for i in range(2, n):
        arr[i] = True

    for i in range(2, ceil(sqrt(n))):
        if arr[i]:
            for j in range(i**2, n, i):
                arr[j] = False

    return [i for i in range(2, n) if (arr[i] and int(i).bit_length() == (int(n).bit_length() - 1))]
