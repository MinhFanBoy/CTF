
from Crypto.Cipher import AES
from pwn import *

# nc blocked2.wolvctf.io 1337
def rec(s, txt) -> bytes:
    s.sendlineafter(b" > ", txt.hex().encode())
    return bytes.fromhex(s.recvline()[:-1].decode())
    
def main() -> None:
    
    s = connect('blocked2.wolvctf.io', 1337)

    s.recvuntil(b"message:")
    s.recvline()
    tmp = bytes.fromhex(s.recvline()[:-1].decode())

    iv, enc_0 = tmp[:16], tmp[16:]
    payload = iv
    
    for i in range(0, len(enc_0), 16):
        enc_1 = rec(s, payload)
        iv, enc_1 = enc_0[:16], enc_1[16:]

        payload = xor(enc_0[i: i + 16], enc_1[16: 32])
        print(payload.decode(), end = "", flush=True)

if __name__ == "__main__":
    main()

