# nc befuddled1.wolvctf.io 1337
from pwn import *

s = connect('befuddled1.wolvctf.io', 1337)
print(s.recvuntil('code? ').decode())
code = """>:#,_$1&>: #v_$
"""

s.sendline(code.encode())
print(s.recv().decode())