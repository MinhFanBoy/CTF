
from pwn import xor
from requests import *
from Crypto.Util.number import *

def decrypt(flag: str):
    flag_hex = flag
    s = "https://aes.cryptohack.org/ecbcbcwtf/" + "decrypt/" + flag_hex
    tmp = get(s).json()
    return tmp["plaintext"]

def encrypt():
    url = "https://aes.cryptohack.org/ecbcbcwtf/encrypt_flag/"
    tmp = get(url).json()
    return int("0x" + tmp["ciphertext"], 16)

def main():
    enc_flag = long_to_bytes(encrypt())
    flag = long_to_bytes(int(decrypt(hex(bytes_to_long(enc_flag))[2:]), 16))
    print(xor(enc_flag[:16], flag[16 : 32]).decode() + xor(enc_flag[16:32], flag[32:]).decode())

if __name__ == "__main__":
    main()
