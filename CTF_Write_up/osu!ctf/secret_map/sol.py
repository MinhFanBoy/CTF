
from pwn import xor
enc = open("secret_map/flag.osu.enc", "rb").read()
know = b"osu file format "

with open("flag.osu", 'wb') as f:
    f.write(xor(xor(enc[:16], know), enc))
