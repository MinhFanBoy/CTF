def de_affine(flag: str, k: list) -> str:

    alphabet = ascii_uppercase
    txt = ""
    d = lambda x: (pow(k[0], -1, len(alphabet)) * (alphabet.index(x) - k[1])) % len(alphabet)
    for x in range(len(flag)):
        txt += alphabet[d(flag[x])]

    return txt
