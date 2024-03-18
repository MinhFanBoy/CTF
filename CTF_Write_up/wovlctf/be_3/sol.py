from pwn import *
# nc befuddled3.wolvctf.io 1337

s = connect('befuddled3.wolvctf.io', 1337)
print(s.recvuntil('code? ').decode())
code = """0_0,,,,_
"""

s.sendline(code.encode())
print(s.recv().decode())

# wctf{truly_th3_m0st_b3fuddl3d_s3r0}
