# Crypto

---

**_Description:_**

A3S_C1R

Do you know all the modes of block cipher??

file: [chall.rar](https://kcsc.tf/files/231f51a78939223975db5b586e1c20a1/A3S_C1R.rar?token=eyJ1c2VyX2lkIjoxOCwidGVhbV9pZCI6bnVsbCwiZmlsZV9pZCI6Mzd9.ZYJ4cQ.u4LGK2QU620oep_CM4OmgZWidn0)

---

Đề bài là về AES mode CTR. Có sẵn 2 enc text dc mã khóa chung key và 1 plain text. Vì trong mode CTR các text dc mã hóa bằng cách xor với key. Mà ta đã có 2 enc cùng key nên nghĩ tới việc xor 2 enc với nhau.

có : 
enc_1 = p_1 xor key

enc_2 = p_2 xor key

=> enc_1 xor enc_2 = p_1 xor key xor p_2 xor key (mà c xor c = 1)

=> enc_1 xor enc_2 = p_1 xor p_2

nên enc_1 xor enc_2 xor p_1 = p_2

vậy flag = enc_1 xor enc_2 xor text
