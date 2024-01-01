# picoCTF

---

AUTHOR: MADSTACKS

**_Description_**

I wanted an encryption service that's more secure than regular DES, but not as slow as 3DES... The flag is not in standard format.

_nc mercury.picoctf.net 37751_ [ddes.py](https://mercury.picoctf.net/static/a31327d353582ee5a6eca77ad7b15aab/ddes.py)

---

Khi xem file ddes.py mình thấy các key có dạng int + "  " , và flag sẽ dc mã hóa 2 lần bằng DES mode ECB bằng các key khác nhau.

Mình thử cách brute force tất cả các cặp key có thể (10^(6))^(2) thì thấy nó quá lớn và khó thực hiên. Nhưng vì ta có thể tự encrypted plaintext nên từ đấy mình có hướng như sau:

Thử encrypt plaint text mình nhập dc để dc enc_plaintext_lần_1, decrypt phần enc_plaintext_lần_2 với tất cả các key có thể để dc enc_plaintext_lần_1.Từ đó tìm xem cái xuất hiện trong cả hai trường hợp chính là enc_plaintext_lần_1 đúng và từ đó mình có thể tìm ra dc 2 cái key.


