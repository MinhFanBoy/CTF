# PicoCTF

src = [PicoCTF](https://play.picoctf.org/practice/challenge/6?category=2&page=5&solved=0)

---

*-Description:_*

Sometimes RSA certificates are breakable
[file.pem](https://jupiter.challenges.picoctf.org/static/c882787a19ed5d627eea50f318d87ac5/cert)

---

Đây là một bào đơn giản mình chỉ cần mở file pem ra là dc. Dùng [PEM decode] ta có dc N. Vì N ở đây rất nhỏ nên ta có thể dễ dàng tìm dc q và p.
4966 306421 059967 = 67 867967 × 73 176001

>picoCTF{73176001,67867967}
