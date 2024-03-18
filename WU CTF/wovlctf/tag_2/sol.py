from pwn import *

def main()-> None:

    # nc tagseries2.wolvctf.io 1337
    s = connect("tagseries2.wolvctf.io", 1337)

    fake_tag = b"\x00" * 16
    s.recv()

    s.sendline(b"GET: flag.txt000")
    s.sendline(fake_tag)
    enc_1 = s.recv()[:-1]

    s.sendline(b"GET: flag.txt000" + len(b"GET: flag.txt000").to_bytes(16, "big") + enc_1)
    s.sendline(fake_tag)
    enc_2 = s.recv()[:-1]

    s.sendline(b"GET: flag.txt001")
    s.sendline(fake_tag)
    enc_3 = s.recv()[:-1]

    s.sendline(b"GET: flag.txt001" + len(b"GET: flag.txt001").to_bytes(16, "big") + enc_3)
    s.sendline(enc_2)
    print(s.recv()[:-1])

if __name__ == "__main__":
    main()