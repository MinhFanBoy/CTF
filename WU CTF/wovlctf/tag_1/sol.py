
from Crypto.Cipher import AES
from pwn import *
from Crypto.Util.Padding import pad, unpad

def main() -> None:
    
    s = connect('tagseries1.wolvctf.io', 1337)

    MESSAGE = b"GET FILE: flag.txt"
    MESSAGE = pad(MESSAGE,16)
    payload = [MESSAGE[i:i+16] for i in range(0, len(MESSAGE), 16)]
    payload.append(MESSAGE)

    s.recv()
    tag = b"\x00" * 16
    s.sendline(payload[0])
    s.sendline(tag)
    s.recv()

    s.sendline(payload[1])
    s.sendline(tag)
    response = s.recv()[:-1]

    s.sendline(MESSAGE)
    s.sendline(response)
    print(s.recv())

    
    
if __name__ == "__main__":
    main()

