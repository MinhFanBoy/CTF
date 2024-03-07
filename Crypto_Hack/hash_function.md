
Tables of contens
-----------------
## I. Kiến thức chung

- Hàm băm (hash functions) là hàm tạo với đầu vào là một dãy dài và đầu ra chỉ chứa một số lượng ký tự xác định nên nó thường được ứng dụng trong cấu  trúc dữ liệu, truyền thông tin ...(ở đây chúng ta sẽ nhìn nó dưới góc độ mật mã học)
- Nó thường được thiết kế theo kiểu hàm một chiều tức không thể giải mã được nó(cho dù biết tất cả về bản rõ thì việc đảo ngược nó vẫn gần như là bất khả thi).
- Thường được sử dụng để xác thực mã hóa, ký văn bản, kiểm tra dữ liêu... (thường được sử dụng trong RSA, ECC,...)
- Cách tần công nó gồm có 3 loại chính:
  + Pre-image attacks: tìm một đầu vào khác có cùng đầu ra với dữ liệu
  + Length extension attack: Thêm thông tin vào  văn bản đã được mã hóa bằng hàm băm
  + Collision resistance:cũng k hiểu cái này lắm kiểu như là brute force để tìm đầu vào ????
- Nói chung, hàm băm cũng có thể bị phá vỡ bởi nhiều cách tấn công nên nó cũng không thật sự an toàn lắm.

## 2. CryptoHack

### 1. Jack's Birthday Hash

---

**_TASK:_**

Today is Jack's birthday, so he has designed his own cryptographic hash as a way to celebrate.

Reading up on the key components of hash functions, he's a little worried about the security of the JACK11 hash.

Given any input data, JACK11 has been designed to produce a deterministic bit array of length 11, which is sensitive to small changes using the avalanche effect.

Using JACK11, his secret has the hash value: JACK(secret) = 01011001101.

Given no other data of the JACK11 hash algorithm, how many unique secrets would you expect to hash to have (on average) a 50% chance of a collision with Jack's secret?

---

Đọc đề ta thấy số ta cần tìm là số lượng đầu vào có thể để ta có thể brute force đầu vào của hàm băm với tỷ lệ thành cộng là 50%.

có đầu ra của hàm băm là 2 ^ 11, giả sử p(k) là xác xuất để k lần thử để có một lần chính xác vậy p(n) = 100%, $p^-(x)$ là tỷ lệ để không lần nào trong số k lần thử chính xác.
Mà $p(k) = ((n - 1)/n) ^ k$ nên tỷ lệ để có 50% thnahf công sẽ là $1 - p(x) = 1 - ((n - 1)/n) ^ k = 0.5$

```py


from math import log10

n = 2 ** 11

print(log10(0.5) / log10((n - 1)/n))
```

> 1420

### 2. Jack's Birthday Confusion

---

**_TASK:_**

The last computation has made Jack a little worried about the safety of his hash, and after doing some more research it seems there's a bigger problem.

Given no other data of the JACK11 hash algorithm, how many unique secrets would you expect to hash to have (on average) a 75% chance of a collision between two distinct secrets?

Remember, given any input data, JACK11 has been designed to produce a deterministic bit array of length 11, which is sensitive to small changes using the avalanche effect.

---

