
L = {a1*v1 + a2*v2 + ... + ak*vk : a1, a2, ..., an ∈ Z}.

Cho một tập hợp các vector phi tuyến v1, v2, ..., vn ∈ Rm, lattice L được tao ra bởi v1, v2, ..., vn là một tập hợp các vector phi tuyến v1, v2, ..., vn với hệ số nguyên.
Thể tích của một latice được tính bằng |det(L)|. Với L và vector dc xây dựng bằng v1, ..., vn.

```sage

L = matrix([[6, 2, -3],[5, 1, 4],[2, 7, 1]])
print(det(L))
# -255 => v_L = 255
```
