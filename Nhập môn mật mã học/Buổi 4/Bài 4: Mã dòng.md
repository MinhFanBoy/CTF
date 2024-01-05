I. Khái niệm
1. Ý tưởng
   + Với ý tưởng cơ bản là sinh dòng khóa z1,z2,...,zn theo một thuật toán nào đó và mã dòng các đặc trưng rõ theo cách
   + Y = y1y2.. = e_z1(x1)e_z2(x2)..
2. Thuật toán
   + Giả sử K là một khóa. Các hàm f_i được sử dụng để sinh ra dãy khóa z_i như sau:
     - z_1 = f(K)
     - z_2 = f(K, z_1)
     - ...
     - z_n = f(K, z_1, ..., z_n-1)

   + Sau đó tính y_i = e_(z_i)(x_i) cứ như vậy cho đến hết các bít rõ
   + Để giải mã nó thì tính z_1, x_1 = d_z_1(y_1) cứ như vậy tới hết các bit rõ
   + Mã dòng được gọi là đồng bộ nếu z_i = f_i(k) với mọi i
   + Mã dòng được gọi là tự đồng bộ nếu z_i = f_i(K, y_i-h, ..., y_i) với mọi i = h + 1, ...
   + mã dòng là tuần hoàn với chu kỳ d nếu z_(i + d) = z_(i) với d <= i
3. Các đặc trưng của mã dòng
   + Thanh ghi dịch phản hồi:
     - Thanh ghi dịch phản hồi (bậc n) là bộ gồm n ô nhở A0, ..., An-1 và một hàm phản hồi f() tác động trên các giá trị của các ô nhớ Ai.
     - Giả sử tại thời điểm t, t = 0,1,2,... giá trị của các ô nhớ Ai là a_i, i = 0, ..,n-1; a_i(t) = {0, 1}, vật thì giá trị của các ô tại thời điểm t + 1 là:
       
       -----------------------------------------------
       |a_i(t + 1) = a_(i + 1)(t) với i = 0, ..., n-2|
       |a_(n - 1)(t + 1) = f(a_n-1(t), ..., a_0(t))  |
       -----------------------------------------------

   + Dãy ghi dịch:
       - Nếu tại ô A0 lấy ra a_k = a_0(k), k >= 0, thì {a_k} là dãy ghi dịch sinh bởi thanh ghi dịch phản hồi bậc n với hàm phản hồi f.
       - Dãy {a_k}, k >= 0 được gọi là dãy ghi nghịch bậc n, nếu tồn rại hàm f():{0,1}^n->{0,1} sao cho:
         - a_(n + k) = f(a_(n - 1 + k), ..., a_k)
         - dàm f trong định nghĩa này được gọi là hàm phản hồi tạo dãy {a_k}. Dãy ghi nghịch dược gọi là tuyến tính (phi tuyến) nếu hàm phản hồi f là hàm tuyến tính (phi tuyến). hàm phản hồi có dạng tổng quát là
         - f(a_0, ..., a_n) = c0 * a0 xor ... xor cn * an
         - trong đó c0, .., cn nhận giá trị trong {0, 1}
   + Độ phức tạp tuyến tính:
     - Độ phức tạp tuyến tính của một dãy nhị phân hữu hạn s, ký hiệu là L(s), là độ dài của LFSR ngắn nhất để sinh ra dãy s
     - Độ phức tạp tuyến tính của một dãy nhị phân vô hạn s, ky hiệu là L(s) được xác định như sau:
       - Nếu s là dãy 0 (s = 0,0,0,0,..) thì l(s) = 0;
       - Nếu không có LFSR nào sinh ra s thì , l(s) = inf
       - Ngược lại,l(s) là độ dài của LFSR ngắn nhất sinh ra s

   + chu kỳ:
     - Dãy s = s0, s1, s2, ... là tuần hoàn bậc N nếu s_i = s_(i + n) với mọi i
     - chu kỳ của một dãy là số nguyên dương nhỏ nhất n mà s tuần hoàn bậc N
   + Tự tương quan:
     - trong dòng khóa gồm các biến ngẫu nhiên độc lập, đồng xã xuất thì quan hệ giữa các phần tử bất kỳ là  độc lập và do đó có sự tương quan bằng 0. Đây là một tính chất tốt của khóa
     - tuy nhiên khi khóa được tạo ra nhờ thuật toan xác định thì các phần tử bất kỳ là không độc lập với nhau vì vậy người ta muốn làm sao khó đạt hệ số gần tương đương 0.

III. Mã Dòng
1. các nguyên lý thiết kế
   + Thiết kế mã dòng dựa  các LFSR
   + Thiết kế mã dòng dựa trên mã khối
2. Thuật toán RC4

   + Mảng S gồm các số từ 1-> 255, với N = 256
   + Thuật toán Key Scheduling Algorithm (KSA): dùng 1 khóa mật như là mầm để tạo trạng thái giả ngẫu nhiên
   + Thuật toán Pseudo Random Generation Algorithm (PRGA): Tạo dòng số giar ngẫu nhiên
     - Bước 1: Khởi tạo mảng S = [0, ..., 255], tạo một vector tạm T, Nếu độ dài khóa là 256 bit thì k = khóa, Nếu >256 bit thì phần tử đầu tiên đưuocj copy lần lượt sang T cho đén hết, sau đó tiếp tục lặp lại cho đến khi đạt 256 bit
     - Bước 2: Thuật toán KSA
     - Bước 3: thuật toán PRGA
     - Bước 4: Mã hóa, giải mã khi luồng khóa cuối cùng được tạo, quá trình mã hóa và giải mã cũng giống nhau, chuỗi văn bản được XOR với luồng khóa được tạo. Nếu đầu vào là bản rõ thì sẽ tạo ra bản mã hóa và ngược lại nếu bản mã hóa thì sẽ cho ra bản rõ
    
     - => ciphertext = e(key) xor plaintext
     - => plaintext = e(key) xor ciphertext
    
3. Ưu nhược điểm

<picture>
   <img src="https://lilthawg29.files.wordpress.com/2021/10/image-223.png?w=768" >
</picture>
 <picture>
   <img src="https://lilthawg29.files.wordpress.com/2021/10/image-224.png?w=" >
</picture>

   
       
