# Crypto Hack

---

Poor Johan has been answering emails all day and the students are all asking the same questions. Can you read his messages?

Challenge files:
  - [johan.py](https://cryptohack.org/static/challenges/johan_335f59b72545e3e27e60453719d50288.py)
  - [output.txt](https://cryptohack.org/static/challenges/output_0ef6d6343784e59e2f44f61d2d29896f.txt)
    
---

Khi xem file output thi thấy có nhiều lần mã hóa RSA với cùng một số e = 3, lập tức nghĩ tới CRT. Đầu tiên để có thể RSA thì các số có yêu cầu phải GCD() = 1

    for x in range(len(n)):
         for y in range(x+1,len(n)):
             print(GCD(n[x],n[y]))
=> thỏa mãn

Ý tưởng :
+ m^3 = c_1 (mod n_1)
+ m^3 = c_2 (mod n_2)
+ m^3 = c_3 (mod n_3)

  Đặt m^3 = x thì dễ thấy nó là CRT. => x => m = x^(1/3)

  
