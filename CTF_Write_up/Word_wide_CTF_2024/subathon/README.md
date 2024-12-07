
### Crypto/subathon

```py
from notaes import notAES
from os import urandom
from time import time


# ugh standard flag shenanigans yada yada
key = urandom(16)
cipher = notAES(key)

# from secret import flag
flag = "FLAG{??????????????????????????????????????}"
flag_enc = cipher.encrypt(flag.encode())
print(f'{flag_enc = }')


# time for the subathon!
st = time()
TIME_LEFT = 30
while time() - st < TIME_LEFT:
    print("=================")
    print("1. Subscrib")
    print("2. Play rand gaem")
    print("3. Quit")
    print("=================")
    choice = str(input(""))
    if choice == "1":
        print("Thank you for the sub!!")
        TIME_LEFT += 30
    elif choice == "2":
        print("Guess the number!")
        ur_guess = int(input(">> "))
        my_number = int.from_bytes(cipher.encrypt(urandom(16)), "big")
        if ur_guess != my_number:
            print(f"You lose, the number was {my_number}")
        else:
            print("Omg you won! Here's the flag")
            print(flag)
    else:
        break
print("The subathon's over! Hope you had fun!!")
```

#### 1. Solution

+ Trong thử thách này ta được cho `flag_enc` tức flag đã được mã hóa và rất nhiều cipher text từ các bytes random. Nhưng hàm ma hóa chính ở đây là `AES` đã bị custom và chỗ bị thay đổi ở đây là s_box.

+ Với S_box mới giá trị `234` không xuất hiện ở trong s_box nên với cấu trúc của AES như này:

```py
        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])
```

sau hàm `sub_bytes` giá trị 234 sẽ không thể xuất hiện và cũng do hàm add round được sử dụng cùng một key nhiều lần nên sau hàm `add_round_key` sẽ tồn tại một giá trị không thể xuất hiện được (`shift_rows` hàm này chỉ thay đổi vị trí của nó chứ giá trị của nó thì vẫn không thay đổi).

+ Mình lấy thật nhiều cipher text để tìm giá trị không duy nhất không có trong khoảng [0, 255] và xor lại giá trị đó với `234` để tìm lại key round và từ key round có thể tìm lại key vì hàm tạo key không thay đổi và từ đó có thể decrypt lại flag.

#### 2. Code

```py

from Crypto.Util.number import *
from tqdm import trange
from aeskeyschedule import reverse_key_schedule
from aes import *
from pwn import *


# context.log_level = "debug"
while True:
    s = process(["python3", "chall.py"])
    s.recvuntil(b"flag_enc = ")
    c = eval(s.recvline().strip())
    # s.interactive()
    def c1():
        s.sendline(b"1")

    def c2():
        c1()
        s.sendline(b"2")
        s.sendlineafter(b">> ", b"00")
        s.recvuntil(b"You lose, the number was ")
        return long_to_bytes(int(s.recvline().strip().decode()))

    k = [set() for i in range(16)]

    # while True:
    for i in trange(10000):
        tmp = c2()
        for i, j in enumerate(tmp[:16]):
            if len(k[i]) < 255:
                k[i].add(j)
    possible_key = []

    for i in k:
        tmp = []
        i = list(i)
        for _ in range(256):
            if _ not in i:
                tmp.append(_)
        possible_key.append(tmp)
    print(possible_key)


    for i0 in possible_key[0]:
        for i1 in possible_key[1]:
            for i2 in possible_key[2]:
                for i3 in possible_key[3]:
                    for i4 in possible_key[4]:
                        for i5 in possible_key[5]:
                            for i6 in possible_key[6]:
                                for i7 in possible_key[7]:
                                    for i8 in possible_key[8]:
                                        for i9 in possible_key[9]:
                                            for i10 in possible_key[10]:
                                                for i11 in possible_key[11]:
                                                    for i12 in possible_key[12]:
                                                        for i13 in possible_key[13]:
                                                            for i14 in possible_key[14]:
                                                                for i15 in possible_key[15]:
                                                                    key = bytes([i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15])
                                                                    key = xor(key, bytes([234]) * 16)
                                                                    key = reverse_key_schedule(key, 10)
                                                                    cipher = AES(key)
                                                                    for _ in range(0, len(c), 16):
                                                                        flag = cipher.decrypt_block(c[_:_+16])
                                                                        print(flag)
```