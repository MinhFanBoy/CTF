import string
import random

flag = "KCSC{s0m3_r3ad4ble_5tr1ng_like_7his}" 

alphabet = string.ascii_letters + string.digits + "!{_}?"
# assert all(i in alphabet for i in flag)


# for i in range(3):
#     k = random.randint(0, len(alphabet))
#     alphabet = alphabet[:k] + alphabet[k+1:]

# key = random.randint(0, 2**512)

# ct = ""
# for i in flag:
#     ct += (alphabet[(alphabet.index(i) + key) % len(alphabet)])

# print(f"{ct=}")
print(alphabet)
ct='2V9VnRcNosvgMo4RoVfThg8osNjo0G}mmqmp'
while True:
    for i in range(3):
        k = random.randint(0, len(alphabet))
        alphabet = alphabet[:k] + alphabet[k+1:]

    try:
        assert all(i in alphabet for i in ct)
        flag  = ""
        key = 17
        for i in ct:
            flag += alphabet[(alphabet.index(i) - key) % len(alphabet)]
        print(flag)
        if "KCSC{" in flag:
            
            print(alphabet)
            print(flag)
            break
    except:
        alphabet = string.ascii_letters + string.digits + "!{_}?"