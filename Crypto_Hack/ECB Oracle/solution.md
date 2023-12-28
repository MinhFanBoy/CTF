# Crypto

---
**_Descriptions:_**

ECB is the most simple mode, with each plaintext block encrypted entirely independently. In this case, your input is prepended to the secret flag and encrypted and that's it. We don't even provide a decrypt function. Perhaps you don't need a padding oracle when you have an "ECB oracle"?

Play at [https://aes.cryptohack.org/ecb_oracle](https://aes.cryptohack.org/ecb_oracle)

---

AES ECB (Electronic CodeBook) mode là chế độ mã hóa dễ dàng bị tấn công bằng cách brute force .
Vì trong ECB mode các plain text sẽ dc chia làm các block mỗi block có 16 bytes. Trong trường hợp len(plaintext) không chia hết cho 16 thì block cuối sẽ được pad thêm để đạt dc 16 bytes(giá trị của các pad sẽ bằng số bytes còn thiếu trong block)

enc(1111111111111111 1111111111111111)("11"*16) = enc(1111111111111111)("11"*8) + enc(1111111111111111)("11"*8)
enc(1111111111111111 11111111111111  )("11"*15) = enc(1111111111111111)("11"*8) + enc(111111111111111\x01)

enc(11111111111flag{}) = enc(11111111111flag{) + enc(}...)

Mà ta có plaintext = input() + flag 
nên nếu mà ta thay đổi các input sao cho flag dc enc trong một block riêng thì ta hoàn toàn có thể bruce dc nó:

với input = pad + flag + pad, flag ban đầu là "", ta chọn ngẫu nhiên một ký tự thuộc alphabet( ở đâu chọn là a)
thì ta có plaintext như sau : 111111111111111a + 111111111111111f + lag... + 

từ đó ta có enc = enc (111111111111111a) + enc(111111111111111f) + enc(lag..)
vì từ đó dễ thấy nếu ciphertext block 1 = ciphertext block 2 thì ký tự ta chọn sẽ giống với ký tự của flag. từ đó flag = "f"

cứ tiếp tục như vậy ta có:

flag = "crypto{abcdefghik"
thì input =  111111111111111c + rypto{abcdefghik + 111111111111111f + lag...

=> enc = enc(111111111111111c) + enc(rypto{abcdefghik) + enc(111111111111111f) + enc(lag...)

dễ thấy nếu ciphertext block 1 + 2 = ciphertxt block 3 + 4 thì flag_guess = flag

vậy :

pad = 16 - len(flag) % 16

input = pad + flag + ký tự brute force + pad

point = 2 *(pad + len(flag) + 1)

thì nếu enc[:point] + enc[point:2 * point] thì có thể kết luận flag + ký có trong flag

> crypto{p3n6u1n5_h473_3cb}
