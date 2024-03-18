
from pwn import *
import HashTools

def main() -> None:
    
    s = connect('tagseries3.wolvctf.io', 1337)
    MESSAGE = b"GET FILE: "
    s.recv()
    enc = s.recv()[:-1].decode()


    magic = HashTools.new("sha1")
    new_data, new_sig = magic.extension(
        secret_length= 1200, original_data=MESSAGE,
        append_data= b"flag.txt", signature= enc
    )
    s.sendline(new_data)
    s.sendline(new_sig)
    print(s.recv())

if __name__ == "__main__":
    main()