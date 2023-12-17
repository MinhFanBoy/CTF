# Misc

---

**_Descriptions:_**

nc 103.162.14.116 14005

---

Khi truy cập vào nc nó yêu cầu ta phải trả về phần tử thứ n của mảng đệ quy với điều kiện:
+ lst[0] = 1
+ n % 2 != thì lst[n] = n + lst[n- 1]
+  else thì lst[n] = n * lst[n - 1]

Để giải quyết bài này khá đơn giản mình dùng quy hoạch động:
b1: check xem đã tính lst[n] chưa nếu có thì trả về nếu chưa thì tính
b2: Khi phải tính thì mình tính lst[n] = n (*)(+) lst[n - 1] bằng cách gọi lst[n-1]
b3: Lưu giá trị lst[n], rồi tả về lst[n]
