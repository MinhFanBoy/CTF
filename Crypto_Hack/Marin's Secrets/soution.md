# Crypto Hack

---
**_Description:_**
I've found a super fast way to generate primes from my secret list.

Challenge files:
  - [marin.py](https://cryptohack.org/static/challenges/marin_15d882fcfd597e1fb7785379b2529875.py)
  - [output.txt](https://cryptohack.org/static/challenges/output_f194012343666ced1a6699d196c8adc5.txt)

---

Bài này nói đến cách tạo số nt từ 2^n - 1. Đây là một cách khá là dễ để phá vì hiện nay có khoảng 50 số nt đã biết từ nó.

C1: Lên Factordb thì dc luôn q, p
C2:
Khi dùng

      print(len(bin(n)[2:]))

thì dc len_bit của n là 4484. Mà:
  + các số q và q không dc quá gần nhau hoặc bằng nhau vì sẽ ảnh hưởng đến tính bảo mật
  + các số q và p không dc quá xa nhau vì nó cx có thể dễ ràng brute

từ đó q ~ P => len_bit(q) ~ len_bit(p)

từ đó len__bit(q) nằm trong khoảng 2048 -> 2242. Do có ít khả năng nên hướng tới quá trình brute tất cả q

> crypto{Th3se_Pr1m3s_4r3_t00_r4r3}

