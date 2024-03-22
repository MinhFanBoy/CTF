Tables_of_contens
=================

### Crypto

Dạo này đang khá rảnh nên mình rành thời gian ra học crypto cũng như học toán a3 thể luôn sắp trượt mọe rồi..
> Có mấy bài khá dễ mình lỡ làm trước rồi giờ lười viết lại nên không có...

### 1. Gram Schmidt

---
**_TASK:_**

```txt
To test your code, let's grab the flag. Given the following basis vectors:

    v1 = (4,1,3,-1), v2 = (2,1,-3,4), v3 = (1,0,-2,7), v4 = (6, 2, 9, -5),

use the Gram-Schmidt algorithm to calculate an orthogonal basis. The flag is the float value of the second component of u4 to 5 significant figures.
```

```py
u1 = v1
Loop i = 2,3...,n
   Compute μij = vi ∙ uj / ||uj||2, 1 ≤ j < i.
   Set ui = vi - μij * uj (Sum over j for 1 ≤ j < i)
End Loop
```
---

Bài này yêu cầu mình sử dụng thuật toán Gram-Schmidt để tính một ma trận khác.

Nói sơ qua về thuật toán trên (mình thấy nói khá khó hiểu):
+ Đây là một thuật toán để trực chuẩn hóa các vector cho trước, trong một không gian tích trong(tích trong là kiểu nhân vector mà mình đã học lớp 10 inner product) với đầu vào là một tập hợp hữu hạn các vector độc lập tuyến tính với nhau. Và tạo ra một tập hợp các vector khác đôi một vuông goc với  với nhau.
+ Công thức tổng quát ở [đây](https://en.wikipedia.org/wiki/Gram%E2%80%93Schmidt_process)

```py

v1 = (4,1,3,-1)
v2 = (2,1,-3,4)
v3 = (1,0,-2,7)
v4 = (6, 2, 9, -5)

v= [v1, v2, v3, v4]
u = [v1]

def _length(v_1 : list, v_2) -> int:
    return sum([x * y for x, y in zip(v_1, v_2)])
def _minus(v_1: list, v_2: list) -> int:
    return tuple(x - y for x, y in zip(v_1, v_2))
def _times(a: int, v: list) -> list:
    return tuple(a * x for x in v)

for vi in v[1:]:

    mi = [_length(vi, uj) / _length(uj, uj) for uj in u]
    uj = vi
    for k in [_times(mij, uj) for (mij, uj) in zip(mi,u)]:
        uj = _minus(uj, k)
    u.append(uj)
print(u)
print(round(u[3][1], 5))
```
