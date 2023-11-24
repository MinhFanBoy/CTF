# Crypto Hack

src = [crypto Hack](https://cryptohack.org/courses/symmetric/aes3/)

---
_Description:_

Complete the add_round_key function, then use the matrix2bytes function to get your next flag.
[Matrix](https://cryptohack.org/static/challenges/add_round_key_b67b9a529ae739156107a74b14adde98.py)

---

> Ý tưởng: Hàm add_round_key là hàm cộng các phần tử ở matrix này với phần tử có vị trí tương ứng tròn matrix khác. Sau khi sử lý xong hàm add thì đến hàm matrix to bytes đã dc học ở bài trước. Matrix2bytes là hàm in ra ký tự trong bảng ASCII theo thứ tự.

 Code:

         state = [
            [206, 243, 61, 34],
            [171, 11, 93, 31],
            [16, 200, 91, 108],
            [150, 3, 194, 51],
        ]
        
        round_key = [
            [173, 129, 68, 82],
            [223, 100, 38, 109],
            [32, 189, 53, 8],
            [253, 48, 187, 78],
        ]
        
        
        def add_round_key(s, k):
            tar = []
            for x in range(0,4):
                temp = []
                for y in range(0, 4):
                    temp.append(state[x][y] ^ round_key[x][y])
                tar.append(temp)
            return tar
        
        
        
        tar = add_round_key(state, round_key)
        
        for x in tar:
            for y in x:
                print( chr(y),end = "" )

> crypto{r0undk3y}
