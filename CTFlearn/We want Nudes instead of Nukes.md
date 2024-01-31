
# Crypto

---

**_TASK:_**

Donald has gone completely crazy. To prevent world chaos, you kidnapped him. Right before the kidnapping he tried to send one encrypted message to his wife Melania. Luckily you intercepted the message. Donald admits that he used AES-CBC encryption - a block cipher operating with a block length of 16 bytes. (here represented by 32 characters)<br /> The message was: {391e95a15847cfd95ecee8f7fe7efd66,8473dcb86bc12c6b6087619c00b6657e}

The format contains first the Initialization vector(IV) and then the cipher text(c) separated by a colon all wrapped in curly braces. {IV,c} After torturing him by stealing his hairpiece, he tells you the plain text of the message is:

FIRE_NUKES_MELA!

As a passionate hacker you of course try to take advantage of this message. To get the flag alter the message that Melania will read: SEND_NUDES_MELA!

Submit the flag in the format: flag{IV,c}

The characters are hexlified, and one byte is represented by two characters; e.g. the string "84" represents the character "F" of the message and so on.

---

Tóm tắt lại đề như sau chuyển từ plaintext ban đầu sang một plaitext khác do ta chọn trong AES-CBC.

Có:

iv = "391e95a15847cfd95ecee8f7fe7efd66"
enc = "8473dcb86bc12c6b6087619c00b6657e"
plaintext = b"FIRE_NUKES_MELA!"
want = b"SEND_NUDES_MELA!"

hmmm.

Từ tính chất giải mã của AES-CBC ta có:

plaintext = enc(cipher, key) $\oplus$ iv $\to$ enc(cipher, key) = plaintext $\oplus$ $iv_1$

want = enc(cipher, key) $\oplus$ $iv_2$ $\to$ want = plaintext $\oplus$ $iv_2$ $\oplus$ $iv_1$ $\to$ $iv_2$ = plaintext $\oplus$ want $\oplus$ $iv_1$

vậy ta chỉ cần gửi lại $iv_2$ và enc là ta sẽ thực hiện được :v Nudes

```py

from Crypto.Cipher import AES
from Crypto.Util.number import *
from pwn import *

iv, enc = bytes.fromhex("391e95a15847cfd95ecee8f7fe7efd66"),bytes.fromhex("8473dcb86bc12c6b6087619c00b6657e")
plaintext = b"FIRE_NUKES_MELA!"
want = b"SEND_NUDES_MELA!"

print(enc, iv)
print(len(plaintext), len(want))

# flag = iv xor enc
# flag xor iv = enc

new_iv = xor(want, iv, plaintext)
print(b"flag{" + new_iv.hex().encode() + b"," + enc.hex().encode() + b"}")
```
