# Crypto

---

**_Description:_**

Is_it_CRT? 
How much do you know about CRT?

file: [chall,rar](https://kcsc.tf/files/89cf2006b93474fb6de3321848614860/Is_it_CRT.rar?token=eyJ1c2VyX2lkIjoxOCwidGVhbV9pZCI6bnVsbCwiZmlsZV9pZCI6NDJ9.ZYJ6_Q.YOy5Hl8cZgTassbLg2GC_zefztY)

---

Thấy khi vào file chall.py ta có 3 n nên giải quyết theo CRT sẽ hiểu quả nhất nhưng điều kiện để có thể sủ dụng CRT là các n đôi một nguyên tố cùng nhau.
Khi thử gcd(n_1, n_2) thì thấy != 1 nên đây là kiểu bài có 3 số q, p ,r các n sẽ là tích của từng đôi một với nhau.

nên n_1 = q * p , n_2 = p * r, n_3 = r * q

từ đó dễ thấy p = gcd(n_1, n_2) => q = n/p. Còn lại thì ta giải theo các bài RSA bình thường là ra.
