
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

secret_key = sha256(b"0").digest()
cipher = AES.new(secret_key, AES.MODE_ECB)
print(cipher.decrypt(bytes.fromhex("3a641a40286eb1611870ca1a8609689793153b1f404037d202b36969d18e2bb61f6ff9e2fc12142c1a53e01f7f17dc17")))
