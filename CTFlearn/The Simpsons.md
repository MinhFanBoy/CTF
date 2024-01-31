# Crypto

---

**_TASK_**

Ya know, I was thinking... wouldn't the Simpsons use octal as a base system? They have 8 fingers... Oh, right! The problem! Ummm, something seems odd about this image... https://mega.nz/#!yfp1nYrQ!LOz_eucuKkjAaDqVvz3GWgbfdKWn8BhussKZbx6bUMg

---

Tải thử ảnh thì ta thấy được các dòng số được dấu trong bytes của ảnh.

```py
encoded = '152 162 152 145 162 167 150 172 153 162 145 170 141 162'
arr = '110 157 167 040 155 165 143 150 040 144 151 144 040 115 141 147 147 151 145 040 157 162 151 147 151 156 141 154 154 171 040 143 157 163 164 077 040 050 104 151 166 151 144 145 144 040 142 171 040 070 054 040 164 157 040 164 150 145 040 156 145 141 162 145 163 164 040 151 156 164 145 147 145 162 054 040 141 156 144 040 164 150 145 156 040 160 154 165 163 040 146 157 165 162 051'
```

đọc kỹ đề thì ta thấy có gợi ý về số ngón tay của simps nên mình có thể thấy nó đang hệ bát phân. Khi chuyển phần encoded sang thập phân và dạng chữ thì ta dc một loạt các chữ cso vẻ không liên quan lắm. Sau khi đọc hướng dẫn dưới bình luận thì mình đem đi decode vergine thì ra flag với key là nnj cũng tương đương với maggine ở dạng chữ,

```py

from string import *

encoded = '152 162 152 145 162 167 150 172 153 162 145 170 141 162'
arr = '110 157 167 040 155 165 143 150 040 144 151 144 040 115 141 147 147 151 145 040 157 162 151 147 151 156 141 154 154 171 040 143 157 163 164 077 040 050 104 151 166 151 144 145 144 040 142 171 040 070 054 040 164 157 040 164 150 145 040 156 145 141 162 145 163 164 040 151 156 164 145 147 145 162 054 040 141 156 144 040 164 150 145 156 040 160 154 165 163 040 146 157 165 162 051'
alphabet = ascii_lowercase

# for i in arr.split():
#     print(chr(int(i, 8)), end='')
# else:
#     print()

Maggie = round(847.63 / 8) + 4
key = chr(Maggie) + chr(Maggie) + chr(Maggie - 4) # key = nnj
enc = [int(x, 8) for x in encoded.split()]
flag = ""
for x in range(len(enc)):
    flag += alphabet[(enc[x] - ord(key[x % len(key)]) + 26) % 26]
    
print('CTFlearn{' + flag + "}")
```
