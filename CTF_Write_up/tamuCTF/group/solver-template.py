from pwn import *
from string import *
# generator = 4 bytes
alphabet = ascii_letters + digits + "_{}"
print(alphabet)

dict = {}

print(f"[+] Starting...")
while True:
    s = remote("tamuctf.com", 443, ssl=True, sni="emoji-group")
    s.recvline()

    s.sendline(alphabet.encode())
    s.recvuntil(b"Your cipher text is: ")
    tmp = s.recvline()[:-1].decode()

    if tmp[0] not in dict:
        dict[tmp[0]] = tmp[1:]

    s.recvuntil(b"The flag is: ")
    enc = s.recvline().strip().decode()

    if enc[0] in dict:
        tmp = dict[enc[0]]

        for i in enc[1:]:
            print(alphabet[tmp.index(i)], end = "")
        
        print(f"\n[+] Done!")
        break


    s.close()