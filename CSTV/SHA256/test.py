# nc 167.71.223.49 3000
from json import *
from pwn import *
from base64 import b64decode, b64encode
from SHA256 import sha256 as SHA256

def send_request(j):
    return s.sendline(dumps(j).encode())
def Bendian_STATE(signature,digest_size,state_blocks):
    state = []
    # if len(signature) != digest_size:
    #     raise ValueError(f"The input hash must be {digest_size} bytes long.")
    for i in range(0,len(signature),digest_size//state_blocks):
        temp = signature[i:i+digest_size//state_blocks]
        state.append(int(temp,16))
    return state
def solve(data, token, len_key, add):
    total_len = (64+len(add))*8
    block = add + b"\x80" + b"\x00" * (64-len(add)-1-8) + total_len.to_bytes(8,byteorder="big")
    state = Bendian_STATE(bytes.hex(token),64,8)
    fake_token = bytes.fromhex(SHA256(block,state))
    fake_data = data + b"\x80" + b"\x00" * (64-len_key-len(data)-1-8) + ((len_key+len(data))*8).to_bytes(8,byteorder="big") + add

    res = (b64encode(fake_data)).decode() + str(b'.' + b64encode(fake_token))
    return res

s = connect("167.71.223.49", 3000)
tmp = {"do": "register", "name": "admin"}
send_request(tmp)
print(s.recv())

token = s.recv().decode().split("\n")[0]
data, token = token.split(".")
data, token = b64decode(data), b64decode(token)
len_key = 32
add = b"&admin=True="

fake_token = solve(data, token, len_key, add)
tmp = {"do": "login", "token": fake_token}
send_request(tmp)
print(s.recv())