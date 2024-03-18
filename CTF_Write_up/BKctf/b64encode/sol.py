
from pwn import *
from base64 import *
import random

# nc 45.77.247.61 7021 (đã chỉnh sửa)

i_max = []

tmp = {}
test = {}
for x in range(50):
    tmp[x] = None
print(tmp.values())

while None in tmp.values():
    s = connect("45.77.247.61", 7021)
    enc = s.recv()[:-1]
    len_flag = enc[0]
    privot = enc[1]
    i_max.append(privot)
    
    enc = enc[2:]
    tmp[(18 + privot) % 50] = xor(b"=", enc[-1])
    test[(17 + privot) % 50] = xor(b"=", enc[-2])

print(f"{len_flag = }")
print(f"{privot = }")
print(f"{enc = }")
print(f"biggest of i is {max(i_max)}")

len_flag = 68
privot = 0
len_key = 50
enc = b"\x184\x161&\n7X#%!]\x11\x00\\'6]%(\x04\x07<\x02;3\x0f\x1d=\x06\x11\x1fK\x0b\x01Y9\\*U=\x01@& [#\x13EK\x07&:WEj!]E%-; \\>% V"
print(len(enc))
print(tmp)
print(test)
key = b""
for x in tmp:
    key = key + tmp[x]
print(key)



for i in range(50):
    encode = ""
    for c in enc:
        encode += chr(c ^ key[i])
        i += 1
        i %= len(key)
    try:
        print(b64decode(encode))
    except:
        pass
