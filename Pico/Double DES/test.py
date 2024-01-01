from binascii import *
from Crypto.Cipher import DES
from tqdm import tqdm

def pad(msg):
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return (msg + " " * pad).encode()

enc_flag = unhexlify("0604b7669afb0274ad46d2ec2471529cfc0c8777d15c433a4f6f2032f4a63f5cb8035cfa7a197e76")
plaintext = pad(unhexlify("11223344").decode())
enc_plaintext = unhexlify("974074be30f76aac")


lst_1 = {}
for x in tqdm(range(999999), desc="KEY_1"):
    key = (f"{x:06}" + "  ").encode()
    cipher = DES.new(key, DES.MODE_ECB)
    lst_1[cipher.encrypt(plaintext)] = key

lst_2 = {}
for x in tqdm(range(999999), desc="KEY_2"):
    key = (f"{x:06}" + "  ").encode()
    cipher = DES.new(key, DES.MODE_ECB)
    lst_2[cipher.decrypt(enc_plaintext)] = key


encrypt_table_set = set(lst_1.keys())
decrypt_table_set = set(lst_2.keys())
for encrypt_decrypt_value in encrypt_table_set.intersection(decrypt_table_set):
    KEY_1 = lst_1[encrypt_decrypt_value]
    KEY_2 = lst_2[encrypt_decrypt_value]
    break

cipher1 = DES.new(KEY_2, DES.MODE_ECB)
msg = cipher1.decrypt(enc_flag)
cipher1 = DES.new(KEY_1, DES.MODE_ECB)
msg = cipher1.decrypt(msg)

print("Flag:" + str(msg))
