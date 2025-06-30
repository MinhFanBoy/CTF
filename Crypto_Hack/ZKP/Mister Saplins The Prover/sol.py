
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime

from pwn import *
import json
from hashlib import sha256
from tqdm import *

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a+b)


def attack(lst, i):
    
    tmp = [lst]
    
    tmp.append([merge_nodes(*tmp[0][i:i+2]) for i in range(0,len(tmp[0]),2)])
    tmp[1] = [i] + tmp[1]
    tmp.append([merge_nodes(*tmp[1][i:i+2]) for i in range(0,len(tmp[1]),2)])
    tmp.append([merge_nodes(*tmp[2][0:2])])
    
    return tmp[-1][0]

nodes = []

for i in range(3, 8):
    s = connect("socket.cryptohack.org", 13432)
    s.recvline()
    s.sendline(json.dumps({"option": "get_node", "node": i}).encode())
    nodes.append(bytes.fromhex(eval(s.recvline().decode().strip())["msg"]))
    s.close()

s = connect("socket.cryptohack.org", 13432)
s.recvline()
s.sendline(json.dumps({"option": "get_node", "node": -1}).encode())
data = bytes.fromhex(eval(s.recvline().decode().strip())["msg"])

for i in trange(256):
    
    brute = long_to_bytes(i)
    hsh = hash256(brute + b"crypto{")
    
    test = attack([hsh] + nodes, data)

    s.sendline(json.dumps({"option": "do_proof", "root": hex(bytes_to_long(test))[2:]}).encode())
    # s.interactive()
    print(s.recvline())
    
"""
crypto{M3rkle_Trees__funny_if_U_can_replay_atk}
"""