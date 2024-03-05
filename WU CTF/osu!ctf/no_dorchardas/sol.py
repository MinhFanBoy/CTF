import subprocess
from pwn import *
from json import *
from base64 import *
from Crypto.Util.number import *
import HashTools
import hashlib

from os import urandom
from random import randint

# nc chal.osugaming.lol 9727

s = connect('chal.osugaming.lol', 9727)

print(s.recvline())
tmp = s.recvline()[:-1].decode()

command = tmp

process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

return_code = process.wait()


stdout, stderr = process.communicate()
print(stdout)
# print(s.recv())
s.recvuntil(b'solution: ')
s.sendline(stdout.encode())

print(s.recvline().decode())
print(s.recv().decode())

s.sendline(b"1")
print(s.recv())


dorchadas_slider = b"0,328,33297,6,0,B|48:323|61:274|61:274|45:207|45:207|63:169|103:169|103:169|249:199|249:199|215:214|205:254,1,450.000017166138,6|6,1:1|2:1,0:0:0:0:"
s.sendline(b64encode(b""))
# b"Okay, I've signed that for you: 971fb642714133db236508c62c903116\n\n--------------------------\n| [1] Sign a beatmap     |\n| [2] Verify a beatmap   |\n--------------------------\nEnter your option: "
print(s.recvline())
print(s.recvline())
print(s.recvline())
print(s.recv())

sig = "17667e6ac270bbf1d433075141e51502"


magic = HashTools.new("md5")
new_data, new_sig = magic.extension(
    secret_length= 244, original_data=b"",
    append_data=dorchadas_slider, signature=sig
)
print(f"{new_sig = }")
print(f"{new_data = }")
s.sendline(b"2")

print(s.recv())
s.sendline(b64encode(new_data))
s.sendline(new_sig)
print(s.recv())
print(s.recv())

"""
[+] Opening connection to chal.osugaming.lol on port 9727: Done
b'proof of work:\n'
s.LptikcWN9B2aj60dF5/IeNT+/+JUgIPQ6gCRLvwgTYj4eCc//ZQQ47uw3i4Wp9MVs580es2T4lJoUQl6YzBH9F0icVqoPyx4o3b4vtepnJ2Cx1l2t/pFSNuQyOk+mEuWE3+aDvf0xfXz0TIBOwQTxcv0uPTIXhBlKBq9WCu4AkIbDicUWpaxm3Mr7bS55OBqnCELw+zUlHEZyQnFks8u/Q==

Welcome to the osu! Beatmap Signer


--------------------------
| [1] Sign a beatmap     |
| [2] Verify a beatmap   |
--------------------------
Enter your option:
--------------------------
| [1] Sign a beatmap     |
| [2] Verify a beatmap   |
--------------------------
Enter your option:
b'Enter your beatmap in base64: '
b"Okay, I've signed that for you: 17667e6ac270bbf1d433075141e51502\n"
b'\n'
b'--------------------------\n'
b'| [1] Sign a beatmap     |\n| [2] Verify a beatmap   |\n--------------------------\nEnter your option: '        
new_sig = '7afc9329d4e9a0a7921bc0186c8d5e8f'
new_data = b'\x80\x00\x00\x00\xa0\x07\x00\x00\x00\x00\x00\x000,328,33297,6,0,B|48:323|61:274|61:274|45:207|45:207|63:169|103:169|103:169|249:199|249:199|215:214|205:254,1,450.000017166138,6|6,1:1|2:1,0:0:0:0:'
b'Enter your beatmap in base64: '
/mnt/c/Users/Ms.Van/Downloads/osu!ctf/no_dorchardas/sol.py:61: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline(new_sig)
b'Enter your signature for that beatmap: '
b"How did you add that dorchadas slider?? Anyway, here's a flag: osu{s3cr3t_sl1d3r_i5_th3_burp_5l1d3r_fr0m_Feiri's_Fake_Life}\n\n--------------------------\n| [1] Sign a beatmap     |\n| [2] Verify a beatmap   |\n--------------------------\nEnter your option: "
"""
