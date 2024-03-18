
from pwn import *
from Crypto.Util.Padding import pad, unpad
def main()-> None:
    # nc blocked1.wolvctf.io 1337

    s = connect("blocked1.wolvctf.io", 1337)
    
    print(s.recvuntil(b"you are logged in as:").decode())
    username = s.recvline().strip()
    print(username)
    print(s.recvuntil(b" > ").decode())
    s.sendline(b"2")

    tmp = bytes.fromhex(s.recvline().strip().decode())
    iv = tmp[:16]
    enc = tmp[16:]
    msg = b"password reset: " + username

    if len(msg) % 16 != 0:

        msg += b'\0' * (16 - len(msg) % 16)
    print(msg[16:32])
    payload = xor(msg[16:32], b"doubledelete\x00\x00\x00\x00", enc[:16])
    print(s.recvuntil(b" > ").decode())
    s.sendline(b"1")
    print(s.recvuntil(b"token > ").decode())
    s.sendline(iv.hex().encode() + payload.hex().encode() + enc[16: 32].hex().encode())
    print(s.recv().decode())


if __name__ == "__main__":
    main()