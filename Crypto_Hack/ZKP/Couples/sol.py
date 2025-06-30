import sys
sys.path.append("../")

from pwn import *
import json

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

s = remote("socket.cryptohack.org", 13415)

power = (p - 1) - 4

G = (int(1), int(1), int(0))

s.sendline(json.dumps({"option": "set_internal_z", "z": hex(power)[2:]}))
s.sendline(json.dumps({"option": "do_proof", "G": str(G), 'hsh': "00"}))
s.interactive()