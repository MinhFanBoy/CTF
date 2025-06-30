
import json
from pwn import *

host = 'socket.cryptohack.org'
port = 13414

s = connect(host, port)
s.recvline()
def send_request(data, s):

    s.sendline(json.dumps(data).encode()) 
    response = s.recvline() 
    return json.loads(response.decode())

def get_nodes_request(layers, s):
    request_data = {
        "option": "get_nodes",
        "nodes": ";".join([f"{layer},{count}" for layer, count in layers.items()])
    }
    return send_request(request_data, s)


def submit_proof(root_hash, s):
    request_data = {
        "option": "do_proof",
        "root": root_hash
    }
    return send_request(request_data, s)

layers_to_request = {0: "-1", 1:-1, 2: -1}
response = get_nodes_request(layers_to_request, s)
print("Get Nodes Response:", response)


