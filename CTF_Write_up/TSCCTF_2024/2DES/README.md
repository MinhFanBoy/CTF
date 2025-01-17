
## Crypto/2DES

---

__**chal.py**__

```py
#!/usr/bin/env python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from random import choice
from os import urandom
from time import sleep

def encrypt(msg: bytes, key1, key2):
    des1 = DES.new(key1, DES.MODE_ECB)
    des2 = DES.new(key2, DES.MODE_ECB)
    return des2.encrypt(des1.encrypt(pad(msg, des1.block_size)))

def main():
    # flag = open('/flag.txt', 'r').read().strip().encode()
    flag = b"flag{this_is_a_fake_flag}"

    print("This is a 2DES encryption service.")
    print("But you can only control one of the key.")
    print()

    while True:
        print("1. Encrypt flag")
        print("2. Decrypt flag")
        print("3. Exit")
        option = int(input("> "))

        if option == 1:
            # I choose a key
            # You can choose another one
            keyset = ["1FE01FE00EF10EF1", "01E001E001F101F1", "1FFE1FFE0EFE0EFE"]
            key1 = bytes.fromhex(choice(keyset))
            key2 = bytes.fromhex(input("Enter key2 (hex): ").strip())

            ciphertext = encrypt(flag, key1, key2)
            print("Here is your encrypted flag:", flush=True)
            print("...", flush=True)
            sleep(3)
            if ciphertext[:4] == flag[:4]:
                print(ciphertext)
                print("Hmmm... What a coincidence!")
            else:
                print("System error!")
            print()

        elif option == 2:
            print("Decryption are disabled")
            print()

        elif option == 3:
            print("Bye!")
            exit()

        else:
            print("Invalid option")
            print()

if __name__ == "__main__":
    main()

```

---

Nhìn vào hàm 

```py
def encrypt(msg: bytes, key1, key2):
    des1 = DES.new(key1, DES.MODE_ECB)
    des2 = DES.new(key2, DES.MODE_ECB)
    return des2.encrypt(des1.encrypt(pad(msg, des1.block_size)))
```

có thể dễ thấy đây làm hàm mã hóa `DES(DES(m)) = c` với 1 key có thể chọn còn 1 key do server lấy random từ danh sách có sẵn. keyset = ["1FE01FE00EF10EF1", "01E001E001F101F1", "1FFE1FFE0EFE0EFE"] với danh sách như thế này thì mình có thẻ thấy đây là nhưng khóa bán yếu của DES nên cái key còn lại mình gửi key bán yếu còn lại lên server để lấy flag.

```py

# nc 172.31.2.2 9487
from pwn import *

s = connect("172.31.2.2", 9487)
# s = process(["python3", "chal.py"])

key1s = ["1FE01FE00EF10EF1", "01E001E001F101F1", "1FFE1FFE0EFE0EFE"]
key2s = ["E01FE01FF10EF10E", "E001E001F101F101", "FE1FFE1FFE0EFE0E"]

payload = b""

for i in range(100):
    s.sendline("1")
    s.sendline(bytes.fromhex(key2s[0]).hex())
    print(s.recvline())
```

