
### Crypto More


---

**_TASK:_**

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import choice
from os import urandom
import socket
import threading

FLAG = b'KCSC{Bingo!_PKCS#7_padding}'

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        for i in range(100):
            x = choice(['ECB','CBC'])
            if x == 'ECB':
                cipher = AES.new(urandom(16), AES.MODE_ECB)
            else:
                cipher = AES.new(urandom(16), AES.MODE_CBC, urandom(16))

            try:
                msg = bytes.fromhex(client.recv(size).strip().decode())
                assert len(msg) <= 16
                client.send(cipher.encrypt(pad(msg,16)).hex().encode() + b'\n')
                ans = client.recv(size).strip().decode()
                assert ans == x
                client.send(b'Correct!\n')
            except:
                client.send(b"Exiting...\n")
                client.close()
                return False

        client.send(FLAG)
        client.close()
        return False


if __name__ == "__main__":
    ThreadedServer('',2000).listen()
    
```

Bài này trôm được từ Dũng

---

Bài này cũng khá dễ. Thấy trước khi được mã hóa msg do ta gửi sẽ được padding bằng pkcs7 nên khi ta gửi msg có đúng len = 16 thì ta sẽ nhận được tin nhắn mã hóa có 32 bit vì pad(msg) = msg + b"\x10" * 16. 
Từ đó dựa vào tính chất của CBC nếu ta gửi 2 block giống hệt nhau thì ta sẽ được enc  có 2 block giống nhau. Từ đó ta gửi đi msg = b"\x10" * 16 nếu 2 block ta nhận được giống nhau thì ta sẽ biết được là nó mã hóa theo dạng nào.

```py
from pwn import *
from json import *

s = remote("localhost", 2000)

for x in range(100):

    s.send((b"\x10" * 16).hex().encode())

    tmp = bytes.fromhex(s.recv()[:-1].decode())

    if tmp[:16] == tmp[16:]:
        s.sendline(b"ECB")
    else:
        s.sendline(b"CBC")
    s.recvline()
print(s.recv().decode())
```
