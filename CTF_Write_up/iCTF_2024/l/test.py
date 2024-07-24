
from AesEverywhere import aes256
import hashlib
import base64
import os
from pwn import xor
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def attack(c: bytes, p: bytes) -> bytes:
    ct = base64.b64decode(c)
    salted = ct[:8]
    salt = ct[8:16]
    c = ct[16:]
    p_ = pad(b"admin", 16)

    return  base64.b64encode(salted + salt + c[:16] + xor(p_, c[16:32], pad(p[32:], 16)) + c[32:])

def xorCrypt(text, key):
    """
    XOR encrypt or decrypt the given text with the key
    @param text: string Text to encrypt or decrypt
    @param key: int Key
    @type text: string
    @type key: int
    @rtype: string
    """
    result = ""
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ key)
    return result



adminusername = "k"
signed_id = hashlib.md5(adminusername.encode()).hexdigest() + adminusername
# signed_id = "ff5db067869c7be71048ffd89efe9dd3" + adminusername
aeskey = os.urandom(16)
authtoken = aes256.encrypt(signed_id, str(aeskey))
authtoken = str(authtoken)
authtoken = authtoken[:-1]
authtoken = authtoken[2:]
authtoken = xorCrypt(str(authtoken), 938123)
authtoken = str(authtoken)


authtoken = xorCrypt(authtoken, 938123)

print(f"Before attack: {aes256.decrypt(authtoken, str(aeskey))}")
authtoken = attack(authtoken, signed_id.encode())
print(f"authtoken: {authtoken}")
print(f"After attack: {aes256.decrypt(authtoken, str(aeskey))}")

