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




> crypto{p3n6u1n5_h473_3cb}
