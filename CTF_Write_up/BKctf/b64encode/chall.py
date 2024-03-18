# B64 Recovery
# nc 45.77.247.61 7021 (đã chỉnh sửa)
import base64
import random

flag = 'BKSEC{still secret}'
flag = base64.b64encode(flag.encode()).decode()
key = "" #guess it if u can
encode = ""
pivot = random.randint(0,len(key)-1)
i = pivot
for c in flag:
    encode += chr(ord(c)^ord(key[i]))
    i += 1
    i %= len(key)
output = chr(len(flag)) + chr(pivot) +  encode
print(output)