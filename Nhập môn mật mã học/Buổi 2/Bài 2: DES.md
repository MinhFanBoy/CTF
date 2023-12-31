1.Tổng quan về DES

+ Đầu vào của DES là các block 64 bit và các đầu ra cũng có 64 bit. Với khóa k có độ dài 56 bit(thực ra ban đầu là 64 bit nhưng trong quá trình mã hóa các bit chia hết cho 8 được lấy để kiểm tra tính chắn lẻ nên còn lại 56)
+Thuật toán : Đâu tiên trước khi đi vào mã hóa nó sẽ chia thông tin của bản rõ thành các khối 64 bit, từng khối này sẽ lần lượt được đưa vào mã hóa. Mỗi lần mã hóa sẽ có 16 chu trình chính.

 2. Chi tiết

có 16 vòng:
ở vòng 1 chúng ta làm các việc sau:
+ Phần tạo khóa: Từ khóa 64 bit ban đầu qua phần (Hoán vị PC-1) Permuted choice - 1 loại bỏ các bit ở vị trí chia hết cho 8(từ đó khóa còn lại 56 bit). Tách các bit còn lại làm 2 phần mỗi phần có 28 bỉt là 28 bit đầu và 28 bit cuối(ký hiệu: 28 bit đầu C0, 28 bit cuối D0)
+ Dịch trái: ở các vòng(1, 2, 9, 16) thì ta dich trái 1 bit, các vòng còn lại dịch trái 2 bit.
+ Sau khi dịch vòng trái cho C0 và D0 thì ta sẽ cho vào hoán vị PC-2 . Hoán vị PC-2 về cơ bản là giống hoán vị PC-1 chỉ khác ở sự hoán vị khi các bít 9, 18, 25, 35, 38, 43 bị lược bỏ. Khi này đầu ra của nó sẽ là 18.Lưu lại kết qur sau khi vòng dịch trái rồi gán nó vào C1, D1

- Phần input: Cho 64 bit qua hoán vị Sau đó lấy 64 bit chia làm 2 phần l0 và R0. Đưa R0 qua hoán vị mở rộng E. Mục đích của nó là để tăng số bit lên 48 để XOR với cả key cũng có 48 bits.
- Hoán vị mở rộng E là lặp lại hai bit cuối của hàng trước hoặc hàng sau.
- Sau khi R0 xor với K0 thì ta cho nó qua vòng s-box để chuyển nó về lại 32 bit.
- Tiếp tục cho hoán vị PC-1. Sau đó lấy L0 Xor với kết quả vừa có. Rồi gán bằng R1.

- Tiếp tực làm như vậy trong 16 vòng. Rồi cho qua hoán vi IP(-1) thì ta sẽ có dc ciphertext.

