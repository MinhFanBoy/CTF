Phần đầu toàn là các mã hóa cổ điển như sau:
  + Shifted cipher
  + Afinne cipher
  + vigenere cipher
  + Hill cipher
  + Hệ mật OTP
  + Hệ mật hoán vị
  + Một số mã khóa khác


Mã shift(mã dịch vòng) : là mã hóa mà chúng ta dịch chuyển vị trí của các chữ cái. Nó khá đơn giản và nổi tiếng nhất là mã Ceasar.
  
Mã affine: là cách mã hóa bằng hàm như sau f(x) = ax + b (mod n). Nó ánh xạ chữ cái có vị trí x thành ax + b (mod n). Để giải mã nó thì ta chỉ cần dùng hàm ngược lại như sau là dc d(x) = pow(a, -1, n) * (x - b) (mod n). Lưu ý: cần chọn a sao cho UCLN(a,n) = 1 vì nó là điều kiện cần thiết để tìm dc nghịch đảo của a trong Zn. Với a = 1 thì mã affine trở thành mã ceasar.

Mã vigenere : là mã tương tự với mã ceasar nhưng với các bước nhảy khác nhau. Với m là số nguyên dương, ta định nghĩa như sau P = C = K = (len(aphabet))^ với khóa k = (k1, k2, ..., km). Ta xác định được: enc(x1, x2, ..., xm) = (x1 + k1, x2 + k2, ..., xm + km), dec(y1, y2, ..., ym) = (y1 - k1, y2 - k2, y3 - k3, ..., ym - km) các phép toán đều được thực hiện trên Z(len()). Từ đó ta có thấy phương pháp brute force không khả thi khi key có thể rất lớn. Trong CTF, thì số key thướng không quá lớn và cùng không quá nhỏ thường trong khoảng [3, 6] giúp dễ tính toán.

Mã khóa chạy: là phương pháp gần giống với mã vigenere, plaintext sẽ được nối tiếp với key. Từ đó kiểu mã này phá vỡ khái niệm chu kỳ thường có. VD: key = FLAG, plaintext = testthu, thì khi mã ta lấy k(F, L, A, G, t, e,s) rồi mã hóa giống mã vigenere.

Mã Hill: Lấy m tổ hợp tuyến tính trên bản rõ để tạo ra m tổ hợp trên bản mã. Cho m là số nguyên dương cố định, với P = C = (Z26)^(m), K = {tổ hợp các ma trận khả nghịch cấp m x m trên }. Với k thuộc K, ta xác 

Mã MHV: Không rõ giải thích thế nào cho dễ hiểu nhưng về cơ bản thì nó thay đổi vị trí của plaintext theo các chỉ số cố đinh(đổi chỗ các cột rồi đọc theo dòng). Đê giải mã các cái này thì ta chỉ cần đổi chỗ lại các cột rồi dọc là ok.

=> Đây là các Mã về cơ bản chỉ đổi vị trí hoặc đổi đổi chữ nên ta hoàn toàn có thể phá mã bằng phương pháp tần xuất

affine:
:-----------------------------
|f(x) = ax + b (mod n)       |
|d(x) = a^(-1)(x - b) (mod n)|
------------------------------

Hill:
:----------------------------
|e(x) = x*k                 | 
|d(x) = x*(k ^ -1)          |
-----------------------------
