# CTFlearn

src = [CTFlearn](https://ctflearn.com/challenge/885)

---

_Decription:_

One of the easiest and earliest known ciphers but with XXI century twist! Nobody uses Alphabet nowadays right? Why should you when you have your keyboard?

**_BUH'tdy,|Bim5y~Bdt76yQ_**

---

Theo gợi ý của bài toán mình lập tức viết một đoạn code caesar với key là các ky tự in thường trên bàn phím thì gặp lỗi. Nên mình tách ra làm hai trường hợp in Hoa và thường.
Nhưng trong quá trình viết key thì bị lỗi khi gặp "{}" trình biên dịch hiểu nhầm nên tốn ka khá thời gian của mình.Khi thử "{ }"thì ok. Còn về caesar cipher cơ bản là rất dễ mình chỉ cần thử các trường hợp có thể là ra.

> Note: caesar cipher là hoán vị vị trí các chữ số với k đơn vị

Code:

        c = "BUH'tdy,|Bim5y~Bdt76yQ"
        
        up = '~!@#$%^&*()_+QWERTYUIOP{ }|ASDFGHJKL:"ZXCVBNM<>?'
        down = "`1234567890-=qwertyuiop[]\ asdfghjkl;'zxcvbnm,./"
        for x in range(2,100):
            for i in c:
                if i in up:
                    print( up[ ( up.index(i) + x ) %len(up) ] ,end = "")
                else:
                    print( down[ ( down.index(i) + x ) %len(down) ],end="")
            print()

Đến đây thì ra dc cái form cơ bản rồi chỉnh lại một ít là ra. 

      ZESjq\wvPZrc1wMZ\q32w(
      XRDkw eb{Xtv2e<X w43e)
      CTFlearn Cyb3r>Cae54r_
      VYG;rstm}Vun4t?Vsr65t+
>>       CTFlearn{Cyb3r_Cae54r}
