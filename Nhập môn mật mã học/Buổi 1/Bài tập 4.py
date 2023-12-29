ciphertext = "ZFFPXNZXXQ"

# y -> p, s -> z

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
from math import gcd
print(alphabet.index("P"))
print(alphabet.index("S"))
print(alphabet.index("Y"))
print(alphabet.index("Z"))


#  15 = a24 + b (mod 26)
#  25 = a18+ b (mod 26)
# => -10 = 6a (mod 26)
# 6 * pow(-10, -1, 26) = a (mod 26)
# have GCD(a, 26) == 1
k = 1
while True:
    if gcd(k, 26) == 1 and (6 * k) % 26 ==(-10 % 26):
        print(k)
        break
    else:
        k += 1
        
#  => a = 7
a = 7
# 15 = 7 * 24 + b (mod 26)
# 15 - 7 * 24 = b (mod 26)

b = (15 - 7 * 24) % 26
print(b)
assert (a * 24 + b ) % 26 == 15 and (a * 18 + b)%26 == 25

def de_affine(flag: str, k: list) -> str:
    txt = ""
    d = lambda x: (pow(k[0], -1, len(alphabet)) * (alphabet.index(x) - k[1])) % len(alphabet)
    for x in range(len(flag)):
        txt += alphabet[d(flag[x])]

    return txt

print(de_affine(ciphertext, [7, 3]))
