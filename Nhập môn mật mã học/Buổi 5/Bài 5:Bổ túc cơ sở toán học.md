
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
+ Cho một tập R != 0 phép toán hai ngôi +, * được gọi là một vành nếu:
  - với phép cộng, R là nhóm Aben
  - Có các tính chất kết hợp, phân phối
  - có tính chất giao hoán thì gọi là vành giao hoán
  - Nếu phép nhân có nghịch đảo và không có thương khác 0( tức là không có hai phần khác 0 mà tích của chúng lại bằng 0), thì nó tạo thành miền nguyên.
4.  Trường
    + Trường là một tập hợp F với các phép cộng và phép nhân, thỏa mãn các tính cahsst sau:
      - F là một vành
      - với phép nhân F/{0} là nhóm Aben
    + có thể nói là với các phép toán cộng, trừ, nhân, chia số khác 0 ta có:
      - a - b = (a) + (-b)
      - a / b = a * (b)^(-1)

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


