from Crypto.Util.number import *
from Crypto.PublicKey.RSA import import_key

pub = open('jumbled/public', 'r').read().replace(' ', '')
pub = import_key(bytes.fromhex(pub).decode())
n, e = pub.n, pub.e
print(n, e)
enc = bytes_to_long(open("jumbled/flag.txt.enc", "rb").read())
pri = open('jumbled/private', 'r').read()
pri = import_key(pri)
print(long_to_bytes(pow(enc, pow(e, -1, (pri.p - 1) * (pri.q - 1)), n)))
# tmp = bytes.fromhex(pri).decode()
# k = tmp[10:20]
# print(k)
# for i in range(len(tmp)):
#     k = tmp[10 * i: 10 * (i + 1)]
#     print(k[8], end = "")
#     print(k[6], end = "")
#     print(k[9], end = "")
#     print(k[5], end = "")
#     print(k[7], end = "")
#     print(k[3], end = "")
#     print(k[1], end = "")
#     print(k[4], end = "")
#     print(k[0], end = "")
#     print(k[2], end = "")

