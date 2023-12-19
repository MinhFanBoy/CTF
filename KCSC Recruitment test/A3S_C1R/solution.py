txt = b"TODO:\n - ADD HARDER CHALLENGE IN CRYPTO\n - ADD FLAG TO THE CHALLENGE\n"
encrypted = "5e07dfa19e2b256c205df16b349c0863a15839d056ada1fb425449f2f9af9563eccca6d15cb01aabbe338c851f7b163982127033787fff49e74e3e09f0aee048a1d5b29f5a"
encrypted2 = "410bc8addf6036125f5fe17d4bb61c00ba565a9e71d1bf846f625eeac5bfa972f9e7c4fd60800ac9aa689f9b280f5a09fd3768674401ac60"

from pwn import xor

enc_1 = bytes.fromhex(encrypted)
enc_2 = bytes.fromhex(encrypted2)

print(xor(enc_1,enc_2,txt))