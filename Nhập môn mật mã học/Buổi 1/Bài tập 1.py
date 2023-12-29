k = [7, 11]
key = "CIPHER"
enc = "BNNIECQDZSSGHG"

from string import ascii_uppercase



def de_vigenere(flag: str, key: str) -> str:

    alphabet = ascii_uppercase
    txt = ""
    for x in range(len(flag)):
        tmp = alphabet.index(flag[x]) - alphabet.index(key[x % len(key)])

        txt += alphabet[tmp % len(alphabet)]
    
    return txt

def de_affine(flag: str, k: list) -> str:

    alphabet = ascii_uppercase
    txt = ""
    d = lambda x: (pow(k[0], -1, len(alphabet)) * (alphabet.index(x) - k[1])) % len(alphabet)
    for x in range(len(flag)):
        txt += alphabet[d(flag[x])]

    return txt

print(de_affine(de_vigenere(enc, key), k))
