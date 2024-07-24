from Crypto.Util.number import *
from binascii import crc_hqx

f = lambda x: (x ** 16 + x ** 12 + x ** 5 + 1) % 2 ** 16
# print(crc_hqx(long_to_bytes(42), 42)) = 44840
print(crc_hqx(long_to_bytes(3), 3))
print(f(6))
for i in range(10000):
    print(crc_hqx(long_to_bytes(i), 9))