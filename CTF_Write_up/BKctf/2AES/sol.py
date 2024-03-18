
from Crypto.Cipher import AES
from pwn import xor

def decrypt(msg, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    enc = cipher.decrypt(msg)
    return enc

enc_1 = bytes.fromhex("e6cb39bae94ce96f2028eac1a4a2e48adaf953a11f34ba98aa1135a495faa16425710d96d855f58f2a04c160a2cd22736d18") 
enc_2 = bytes.fromhex("1c185c44ef45d8330cffdee06ed3a8efe55c3af159c58d53beee7c96f8026047")
enc_flag = bytes.fromhex('ba0f66f830aee235dffd01c5cf4216970da64de0e35e03182dcea28ad27734d45c7f53d45e606cf7069a178ab45e9b0b07290c1c0bca760d68628a08a5d2dc30f2c8db614ec0cdad531f5b8df59883bd9e67bc4b076c4f05380f29d085ad8046886dd5a76c50311f68153c')


key_1 = enc_1[:16]
enc_1 = enc_1[16:]
iv_2 = enc_2[:16]
enc_2 = enc_2[16:]
iv_3 = enc_flag[:16]


enc = xor(b'I\'m the author. I will hint you...', enc_1)[:16]

cipher = AES.new(key_1, AES.MODE_ECB)

iv_1 = cipher.decrypt(enc)
key_2 = iv_1

print(decrypt(enc_2, key_2, iv_2))
print(decrypt(enc_flag, key_2, iv_3))