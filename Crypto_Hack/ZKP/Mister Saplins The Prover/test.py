
from hashlib import sha256
import os

FLAG = b"crypto{???????????????????????????????????????}"
flen = len(FLAG)
assert flen == 47

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a+b)
secret = os.urandom(64-flen)
datas = secret + FLAG
nodes = []
print([i for i in range(0,64,8)])
nodes.append([hash256(datas[i:i+8]) for i in range(0,64,8)])
print([nodes[0][i:i+2] for i in range(0,8,2)])
nodes.append([merge_nodes(*nodes[0][i:i+2]) for i in range(0,8,2)])
nodes.append([merge_nodes(*nodes[1][i:i+2]) for i in range(0,4,2)])
print([nodes[1][i:i+2] for i in range(0,4,2)])
nodes.append([merge_nodes(*nodes[2][0:2])])
print(nodes[2][0:2])
print(nodes[0])
for i in range(3):
    following_node = nodes[i+1][0]
    nodes[i].append(following_node)

print(nodes)
print(len(nodes[0]))