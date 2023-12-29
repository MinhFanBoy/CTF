1.Tổng quan về DES

+ Đầu vào của DES là các block 64 bit và các đầu ra cũng có 64 bit. Với khóa k có độ dài 56 bit(thực ra ban đầu là 64 bit nhưng trong quá trình mã hóa các bit chia hết cho 8 được lấy để kiểm tra tính chắn lẻ nên còn lại 56)
+Thuật toán : Đâu tiên trước khi đi vào mã hóa nó sẽ chia thông tin của bản rõ thành các khối 64 bit, từng khối này sẽ lần lượt được đưa vào mã hóa. Mỗi lần mã hóa sẽ có 16 chu trình chính.

 2. Chi tiết

có 16 vòng:
ở vòng 1 chúng ta làm các việc sau:
+ Phần tạo khóa: Từ khóa 64 bit ban đầu qua phần (Hoán vị PC-1) Permuted choice - 1 loại bỏ các bit ở vị trí chia hết cho 8(từ đó khóa còn lại 56 bit). Tách các bit còn lại làm 2 phần mỗi phần có 28 bỉt là 28 bit đầu và 28 bit cuối(ký hiệu: 28 bit đầu C0, 28 bit cuối D0)
+ Dịch trái: ở các vòng(1, 2, 9, 16) thì ta dich trái 1 bit, các vòng còn lại dịch trái 2 bit. 
