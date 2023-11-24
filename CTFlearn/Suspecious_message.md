# Crypto Hack

---

_Decription:_

Hello! My friend Fari send me this suspecious message: 'MQDzqdor{Ix4Oa41W_1F_B00h_m1YlqPpPP}' and photo.png. Help me decrypt this!

- [Photo](https://ctflearn.com/challenge/download/887)

Bài bày mình vô tình đọc bình luận nên biết luôn nó là flayfair cipher. Dù đã biết kiểu hoạt động của nó nhưng mình vẫn tốn nhiều thời gian để code cái decrypt xong flag vẫn dell ra nên ngồi mò flag.

> Note:Playfair cipher[Wiki](https://en.wikipedia.org/wiki/Playfair_cipher)
>
> nó chủ yếu là dùng ma trận rồi thay thế các ký tự với nhau trong ma trận đó:
> + nếu cùng hàng thì hàng +1
> + cùng cột thì cột +1
> + nếu chéo nhau thì lấy đường chéo


Code:

            c = 'MQDzqdor{Ix4Oa41W_1F_B00h_m1YlqPpPP}'
            
            
            up_key = [['Q','W','E','R','T'],
            ['Y','U','I','O','P'],
            ['A','S','D','F','G'],
            ['H','K','L','Z','X'],
            ['C','V','B','N','M']]
            
            def key_index( lst: list, c: str) -> list :
                for x in range(len(lst)):
                    if c in lst[x]:
                        return [x, lst[x].index(c)]
            from string import ascii_uppercase
            

            low_key = []
            for x in up_key:
                temp =[]
                for y in x:
                    temp.append(y.lower())
                low_key.append(temp)
            
            c_2 = c.upper()
            
            
            p = ""
            i = 0
            while i < len(c)-1:
                while (c_2[i] not in ascii_uppercase):
                    p += c_2[i]
                    i+=1
                x = key_index(up_key,c_2[i])
                i+=1
                while (c_2[i] not in ascii_uppercase):
                    p += c_2[i]
                    i+=1
            
                y = key_index(up_key,c_2[i]) 
                i+=1
             
                if x[0] == y[0]:
                    p += up_key[x[0]][(x[1] - 1) % 5]
                    p += up_key[y[0]][(y[1] - 1) % 5]
                elif x[1] == y[1]:
                    p += up_key[(x[0] - 1) % 5][x[1]]
                    p += up_key[(y[0] - 1) % 5][y[1]]
                else:
                    p += up_key[x[0]][y[1]]
                    p += up_key[y[0]][x[1]]
            for x in range(0,len(p)):
                if c[x].islower():
                    print(p[x].lower(),end="")
                else:
                    print(p[x],end="")

Dù code chưa dc tối ưu nhưng đã có dc một ít manh mối và flag ->CTFlearn{Pl4Yf41_1RS_00Cl_1CPheOoOO

cùng với mẫu của ciphertext thì mình có dc flag

> CTFlearn{Pl4Yf41R_1S_C00l_C1PheRrRR}





