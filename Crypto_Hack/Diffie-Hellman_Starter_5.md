# Crypto Hack

src = [crypto Hack](https://cryptohack.org/courses/public-key/dh-starter-5/)

---

***_Desciption:_*

Alice sends you the following IV and ciphertext:

{'iv':'737561146ff8194f45290f5766ed6aba','encrypted_flag':'39c99bf2f0c14678d6a5416faef954b5893c316fc3c48622ba1fd6a9fe85f3dc72a29c394cf4bc8aff6a7b21cae8e12c'}

Decrypt this to obtain your flag!


---

Ta có g, p,a,b, B ở đề bài nên ta dễ dàng tính được share_key = pow(B, a, P). Mình sẽ sử dụng code có sẵn trong đề bài để decrypt là xong
[decrypt.py](https://cryptohack.org/static/challenges/decrypt_08c0fede9185868aba4a6ae21aca0148.py)

