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
       |a_i(t + 1) = a_(i + 1)(t) với i = 0, ..., n-2
       |a_(n - 1)(t + 1) = f(a_n-1(t), ..., a_0(t))

   
       
