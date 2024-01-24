
### Yêu cầu chung:

+ Nắm được kiến thức cơ bản về đại số học
+ Cách các cấu trúc đại số được ứng dụng trong mật mã

I. Cấu trúc đại số
1. Định nghĩa nhóm: tập hợp G được gọi là một nhóm nếu nó thỏa mãn các tính chất sau với mọi a, b, c thuộc G:
   + Tính kết hơp( trong phép cộng và nhân)
   + Có phần tử đơn vị e : a * e = a
   + Có phần tử nghịch đảo a ^ -1 : a * a ^ -1 = e
   + có phần tử 0 sao cho : a + 0 = a
   + Nếu có thêm tính chất giao hoán : a*b = b*a thì còn dc gọi là nhóm Aben

- cấp của một nhóm G chính là số phần tử của G
- Cấp của phần tử a trong nhóm G chính là số nguyên dương nhỏ nhất m thỏa mãn : a ^ m = e, trong đó e là phần tử đơn vị
- Kí hiệu cấp của nhóm G = ord(G) hoặc |G|; Cấp của phần tử a là |a| hoặc ord(a)
2. Định nghĩa nhóm xyclic:
  + G được gọi là nhóm xyclic nếu nó có chứa một phần tử a sao cho mọi phần tử của G đều là lũy thừa của a
  + a được gọi là phần tử sinh( phần tử nguyên thủy của nhóm G)
3.Vành:
+ Cho một tập $R \neq \theta$ phép toán hai ngôi +, * được gọi là một vành nếu:
  - với phép cộng, R là nhóm Aben
  - Có các tính chất kết hợp, phân phối
  - có tính chất giao hoán thì gọi là vành giao hoán
  - Nếu phép nhân có nghịch đảo và không có thương khác 0( tức là không có hai phần khác 0 mà tích của chúng lại bằng 0), thì nó tạo thành miền nguyên.
4.  Trường
    + Trường là một tập hợp F với các phép cộng và phép nhân, thỏa mãn các tính chất sau:
      - F là một vành
      - với phép nhân F/{0} là nhóm Aben
    + có thể nói là với các phép toán cộng, trừ, nhân, chia số khác 0 ta có:
      - a - b = (a) + (-b)
      - a / b = a * (b)^(-1)
      - Tính chất phân phối cộng và nhân: $a * (b + c) = a * b + a * c$
      - Một đa thức bậc một $a * x = b$ chỉ có một nghiệm duy nhất $x = a' * b$ với a' là nghịch đảo của (F, *)   

II. Số học modulo
1. Tính chia hết: Chia số nguyên a cho n được thương là số nguyên q, a = nq
   => a chia hết cho n hay a là bội số của n hay n là ước số của a ký hiệu n|a
2. Cho hai số nguyên a và n (n > 1)thực hiện phép chia a cho n ta sẽ được hai số nguyên q và r sao cho:
   => a = nq + r , 0 < n < n

   trong đó:
   + q là thương
   + n là số chia
   + a là số bị chia
   + r là dư

   Định nghĩa quan hệ đồng dư trên tập số nguyên : a = b (mod n) khi và chỉ khi a và b có phần dư như nhau khi chia cho n

   Vd : 100 = 1 = 34 (mod 11)

   Đại diện của a mod n: Số b được gọi là đại diện của a theo mod n , nếu:
   + a = b (mod n) (hay a = qn + b , 0 <= b < b)
   3. Các phép toán số học trên modulo:

      Về cở bản các phép tính trên mod n cũng tương đương như trong R.
      + a mod n + b mod n = (a + b) mod n
      + a mod n x b mod n = (a x b) mod n

      Khi thực hiện các phép tính trên mod n ta có thể thay a, b bằng các đại diện của nó trong tập {0, ..., n - 1}
      
      Trong trường Zn, các tính chất như giao hoán, kết hợp phân phối có thể sử dụng.

4. Ước số chung
   + Một số được gọi là ước số chung của a, b nếu q|b và q|a
   + Số nguyên d dược gọi là ước chung lớn nhất nếu mọi ước chung khác của a, b đề là ước số của d
   + Một số dược gọi số nguyên tố nếu nó chỉ có ước chung là 1 và chính nó với nọi số nguyên nhỏ hơn nó
   + Hai số a, b được gọi là số nguyên tố cùng nhau nếu gcd(a, b) = 1
   +  Nếu b > 0 và b | a thì gcd(a, b) = b
   +  Thuật toán euclid dùng để tính u * a + v * b = gcd(a, b)
  
```py
def gcd(a: int, b: int) -> int:

    while b:
        a, b = b, a % b
    return a
```

  + Dùng euclid extended để tìm phần tử nghịch đảo
5. Số nguyên tố

+ Số nguyên tố là số chỉ có ước là 1 và chính nó. Nó không thể được viết thành tích của các số nguyên tố khác.
+ Về lý thuyết số nguyên tố có vô hạn.
+ Định lý fermat nhỏ:
  + với n là số nguyên tố, gcd(a, n) = 1,phi là số các số nguyên tố cùng nhau trong khoảng từ [1, n - 1] với n, ta luôn có $a ^ {phi} = a \pmod{n}$
  + hay ta có thể nói $a ^ {phi}| n$(a mũ phi luôn chia hết cho n)
+ Hàm $\phi(n)$ còn được gọi là thặng dư đầy đủ của n.
+ một tập $z_n ^ {*} = \{ a \in z_n ; gcd(a, n) = 1 \}$.
+ Một vài tính chất của hàm $\phi(n)$:
  + nếu n là prime thì $\phi(n) = n - 1$
  + nếu gcd(m, n) = 1 thì $\phi(m * n) = \phi(n) * \phi(m)$
  + nếu $n = a^{x_1} * b^{x_2} ....$ với a, b, c ... là prime thì $\phi(n) = n * (1 - 1 / a) * (1 - 1 / b) ...$

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/aeab90f9-46dc-46fc-ac94-2c3e7167e9f1)

![image](https://github.com/MinhFanBoy/CTF/assets/145200520/109fc539-804b-4215-a347-73d378626347)

 + $Z_n^{*}$ có phần tử sinh khi $n = 2, 4, 2 * p ^ k \quad \forall k \in R, \text{p là số nguyên tố lẻ}$
 +  Nếu $\alpha$ là phần tử sinh trong $Z_n^{*}$ thì $\beta ^ i \pmod{\phi(n)}$
 +  
