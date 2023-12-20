# Crypto 

---

**_Description:_**

Basic Math(medium)

Crypto101: MODULAR ARITHMETIC

nc 103.162.14.116 16002

file: [chall.py](https://kcsc.tf/files/9b92029f265aff782273aa7b9cf9f1e4/chall.py?token=eyJ1c2VyX2lkIjoxOCwidGVhbV9pZCI6bnVsbCwiZmlsZV9pZCI6NDZ9.ZYJziQ.oUXmzOfmeU4Wx-k7C39-EEUH7zc)

---

Sau khi tải file chall.py, đọc file ta thấy đây là bài toán yêu cầu ta nhập các số x, h sao cho thỏa mãn hàm verify. 

    def verify(g, p, y, x, k, h):
    
      return (y*x*pow(g, k, p)) % p == pow(g, h, p)

=> x * y * (g ^ k mod p ) mod p == g ^ h mod p

=> x * y * g ^ k === g ^ h (mod p)

=> x * y * g ^ (k - h) == 1 (mod p)

if x * y = 1 (mod p) and g ^ (k - h) = 1 (mod p) => x * y * g ^ (k - h) = 1 (mod p)

nên từ đây ta sẽ chia nhỏ bài toán thành hai bìa toán nhỏ hơn :
+ x*y = 1 (mod p) = > x = y ^ (-1) mod p
+ g ^ (k - h) = 1 (mod p) => k = h

Nhưng nếu dừng ở đây thì ta chỉ có 1 cặp nghiệm nên phải tìm thêm các cặp nghiệm đúng khác
có : x * y * g ^(k - h - k) * g ^ k == 1 (mod p)

nên ta có thể viết x dưới dạng tích của các số g như sau:
:---------------------------
|x = g ^(i) * pow(y, -1, p)|
|h = 2*k                   |
----------------------------



  


