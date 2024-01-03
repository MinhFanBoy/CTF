
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
    <img src="https://lilthawg29.files.wordpress.com/2021/06/image.png"  width="300" height="400">
  </picture>

   Tùy thuộc vào key mà ta sẽ có số vong lặp khác nhau:
   
   <picture>
      <img src="https://lilthawg29.files.wordpress.com/2021/06/image-2.png" width="30%" height="30%">
   </picture>

2. Chi tiết
   + b1 : khởi tạo plaintext kết hợp với key thông qua addRoundKey
   + b2 : Lặp mã hóa, sử dụng kết quả của bước 1 rồi thông qua 4 hàm chính.
   + b3 : Sau N - 1 vòng, ta cho nó qua 3 hàm (bỏ qua MixColumns) để hoàn thành mã hóa.
3. Cơ sở toán học của AES
      + Trong AES các phép toán đưuocj thực hiện trên trường hữu hạn GF(2^8)
      + Phép cộng: A( a1, a2, a3,..) B( b1, b2, b3, ...) => C = A + B = (c1, c2, c3, ...) với c_i = (a_i + b_i) mod 2
      + Phép nhân: Được thưc hiện trên trường GF(2^8) bằng cách nhân 2 đa thức trong modul bất khả quy m(x).Trong AES m(x) = x^8 + x^4 + x^3 + x + 1
      + Phép xtime: (là phép nhân với x) đọc k hiểu j cả hic

III. Tiêu chuẩn mã
1. Tiêu chuẩn mã nâng cao AES-Rijndael
   có đặc trưng sau:
   + vòng lặp hơi khác so với thông thường
   + chia dữ liệu thành 4 khối - 4 byte
   + thao tác trên cả khối mỗi vòng
   + Thiết kế để chống lại các kiểu tấn công đã biết , tốc độ nhanh và dễ mã hóa, thực hiện được trên nhiều CPU
   + Chi tiết:
     + có 10/12/14 vòng lặp với các 128, 192, 256 bit tương ứng
     + phép thế S_box thì dùng 1 s_box cho từng bytes
     + Trộn côt (nhân ma trận trên các côt)
     + Cộng khóa vòng (Xor trạng thái với khóa vòng)
2. Sơ đồ mã hóa
   + SubBytes - mỗi bytes của state được thay thế bằng 1 bytes khác trên S-box
     - Là quá trình thay thế phi tuyến tính trong đó mỗi bytes được thay thế bằng một bytes khác trong bảng tra
     - S-box là bẳng 16 x 16 chứa hoán vị của 256 ký tự
     - Mỗi bytes trạng thái được thay thế bởi 4 bit trái và cột xác định bởi 4 bit phải
     - VD: 6D sẽ được thay thế bởi S-box[6][D]
     - Hộp thế s-box được xây dựng trên phép biến đổi phi tuyến (cái này không hiểu lắm)
   + ShiftRows : đổi chỗ dịch tái các hàng, theo quy tăc hàng n thì dịch n vị trí
   + MixColums : Hàm này thay đổi giá trị của từng cột bằng cách xor với ma trận

      <picture>
         <img src="https://lilthawg29.files.wordpress.com/2021/09/image-238.png?w=1024" width="70%" heigth="70%"
      </picture>

   + AddRoundKey: Mỗi vòng gồm 32 bit dc sinh ra bởi mở rộng khóa. Lấy cộng giữa hai ma trận
   + KeyExpansion: Được thực hiện theo hàm quy nạp.
   + Với Rcon = [01, 02, 04, 08, 10, 20, 40, 80, 1b, 36]
   <picture>
      <img src="https://lilthawg29.files.wordpress.com/2021/09/image-244.png?w=1024" width="70%" heigth="70%"
   </picture>
 

3. Độ an toàn
   + tính chất phức tạp của biểu thức s-box trên GF(2^8) cùng với hiệu ứng khuếch tán giúp cho thuật toán không bị phân tích bằng phương pháp nội suy
   + Rcon khác nhau hạn chế tính đối xứng
   + Tính chất phi tuyến tính
   + Các cấu trúc hóa giải mã khác nhau hạn chế dc khóa yếu

IV. Các chế độ hoạt động

1. ECB
   + Các thông tin sẽ được chia thành các khối độc lập, sau đó mã từng khối riêng lẻ với nhau
   + Các Khối được mã độc lập với các khối khác C_i = E(P_i), do vậy nó đưuocj dùng để truyền an toàn từng giá trị riêng lẻ
   + Tính chất:
       - Các khối mã như nhau sẽ có bản mã giống nhau(dưới cùng một khóa)
       - Sự phụ thuộc không có nên việc thay đổi sắp xếp các block với nhau thì các bản rõ cũng phải được sắp xếp lại tương ứng
       - Tính lan sai : Khi một hay nhiều bit sai trong một khối đơn lẻ thì nó chỉ ảnh hưởng trong khối đó và không ảnh hưởng tới các khối khác
       - Nó có thể sứ lý nhiều khối song song
2. CBC
   + Mẩu tin được chia thành các khối
   + Các block sếp thành dãy trong quá trình mã hóa, giải mã    





