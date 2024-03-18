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

