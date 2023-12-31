
I. Giới thiệu 
1. Tổng quan
   
   Với plaintext = 128 bit, key = 128 bit, 192 bit, or 256 bit. Trong khi mã hóa có các khóa mở rộng được sinh ra từ chu trình Rijndeal.
   Hầu hết các phép toán trong AES đều được thực hiện trên trường hữu hạn của các bytes. Mỗi khối 128 bit dc chia thành 4 cột với mỗi cột 16 bytes xếp thành một ma trận 4x4, còn dược gọi là ma trận trạng thái.
   Tùy thuộc vào độ dài của khóa mà ta có số lần lặp trong một vòng khác nhau.

2. Các bước chính
   - Quá trình sinh khóa
   - Quá trình mã hóa
II.Thuật toán
1. Mô hình thuật toán
   AES là thuật toán mã khối đối xứng(bản nâng cấp của DES-64)
   Có N vòng lặp và có N-1 vòng lặp chính(1 -> N - 1).Chủ yếu thực hiện các hàm sau:
   + Subbytes - thay thế các bytes dữ liệu bằng bytes phụ
   + Shifrows - dịch vòng dữ liệu
   + Mix columns - trộn dữu liệu
   + AddRoundKeys - chèn khóa vòng

  <picture>
    <img src="https://lilthawg29.files.wordpress.com/2021/06/image.png">
  </picture>
