
Hiện không còn sv bài này và mất luôn cả đề.

Bài này nói về quá trình tấn công mở rộng chuỗi trong SHA256.
Ý tưởng:
+ với token = sha256(iv, secret + data) sau khi truyền dữ liệu đi thì nó sẽ so sánh data mà ta gửi đi bằng cách hash nó với secret
+ fake_data = data + msg
+ fake_token = sha256(token, secret + data + msg) ,với secret thì chỉ cần biết độ dài

thì ta hoàn toàn có thể truy cập dược vào
(code trộm từ Dũng :v)
(có thể sài tool https://github.com/viensea1106/hash-length-extension/tree/main?tab=readme-ov-file)
