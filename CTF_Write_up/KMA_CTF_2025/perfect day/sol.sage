
from Crypto.Util.number import getPrime, bytes_to_long

import os
os.environ["TERM"] = "xterm"

from pwn import *

s = connect("36.50.177.41", 5001)
# s.interactive()
s.recvline()
context.log_level = "debug"

soundtrack = [
    b"House Of The Rising Sun",
    b"the Dock of the Bay",
    b"(Walkin' Thru The) Sleepy City",
    b"Redondo Beach",
    b"Pale Blue Eyes",
    b"Brown Eyed Girl",
    b"Feeling Good",
    b"Aoi Sakana",
    b"Perfect Day"
]

for i in range(32):

    p = eval(s.recvline().decode().split("=")[1].strip())
    hint = eval(s.recvline().decode().split("=")[1].strip())
    h = ((hint - 1) // p)
    for song in soundtrack:
        print(song)
        padded_song = song + b"0xff"*(256 - len(song))
        padded_song = bytes_to_long(padded_song)
        if (h * pow(padded_song, -1, p)) % p in list(range(1, 4096)):
            print("Found song:", song.decode())
            s.sendline(song.decode())
            s.recvline()
            break