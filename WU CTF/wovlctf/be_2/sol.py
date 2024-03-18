from pwn import *
# nc befuddled2.wolvctf.io 1337
s = connect('befuddled2.wolvctf.io', 1337)
print(s.recvuntil('code? ').decode())
code = """,,,,,,,,,,,,,,,_
"""
s.sendline(code.encode())
print(s.recv().decode())

# wctf{4_0n3_l1n3_turn_0f_3v3nt5}