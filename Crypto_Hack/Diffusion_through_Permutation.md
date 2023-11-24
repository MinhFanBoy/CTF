# Crypto Hack

src = [Crypto Hack](https://cryptohack.org/courses/symmetric/aes5/)

---

_Description:_

We've provided code to perform MixColumns and the forward ShiftRows operation. After implementing inv_shift_rows, take the state, run inv_mix_columns on it, then inv_shift_rows, convert to bytes and you will have your flag.

Challenge files:
  - [diffusion.py](https://cryptohack.org/static/challenges/diffusion_ee6215282094b4ae8cd1b20697477712.py)

---

Đề bài cho cho một file và yêu cầu viết hàm inv_shift_row và chỉnh sửa một ít để ra dc đáp án. Ban đầu, nghĩ ngay đến việc đổi lại vị trí bằng cách thay đổi vị trí của các phần tử bằng iter nên mình bắt tay vào code luôn và dc luôn flag -> ez

Code:

        def shift_rows(s):
            s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
            s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
            s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
        
        
        def inv_shift_rows(s):
            s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
            s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
            s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]
        
            return s
        
        
        
        
        # learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
        xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
        
        
        def mix_single_column(a):
            # see Sec 4.1.2 in The Design of Rijndael
            t = a[0] ^ a[1] ^ a[2] ^ a[3]
            u = a[0]
            a[0] ^= t ^ xtime(a[0] ^ a[1])
            a[1] ^= t ^ xtime(a[1] ^ a[2])
            a[2] ^= t ^ xtime(a[2] ^ a[3])
            a[3] ^= t ^ xtime(a[3] ^ u)
        
        
        def mix_columns(s):
            for i in range(4):
                mix_single_column(s[i])
            
            return s
        
        
        def inv_mix_columns(s):
            # see Sec 4.1.3 in The Design of Rijndael
            for i in range(4):
                u = xtime(xtime(s[i][0] ^ s[i][2]))
                v = xtime(xtime(s[i][1] ^ s[i][3]))
                s[i][0] ^= u
                s[i][1] ^= v
                s[i][2] ^= u
                s[i][3] ^= v
        
            return mix_columns(s)
        
        
        state = [
            [108, 106, 71, 86],
            [96, 62, 38, 72],
            [42, 184, 92, 209],
            [94, 79, 8, 54],
        ]
        
        s = inv_mix_columns(state)
        print(s)
        s = inv_shift_rows(s)
        
        for x in s:
            for y in x:
                print(chr(y),end="")

>> crypto{d1ffUs3R}
