# Crypto Hack

src = [Crypto Hack](https://cryptohack.org/courses/public-key/parameter_injection/)

---

**_Description:_**

You're in a position to not only intercept Alice and Bob's DH key exchange, but also rewrite their messages. Think about how you can play with the DH equation that they calculate, and therefore sidestep the need to crack any discrete logarithm problem.

Use the script from "Diffie-Hellman Starter 5" to decrypt the flag once you've recovered the shared secret.

Connect at socket.cryptohack.org 13371

---

Sơ đồ: A <-> M <-> B

Ta sẽ lấy thông tin dc A gửi đi chỉnh sủa nó rồi gửi lại cho B. Dễ thấy 

Nếu B = p thì C_A = pow(p, a, p) = 0
    A = p thì C_B = pow(p, b, p) = 0

Nên ta chuyển thay đổi A với B  = p rồi gửi cho Alice và Bob rồi ta sẽ có iv, cipher_text, share_key = 0. Rồi sủ dụng file decrypt có sẵn là ta có cờ.

code:


    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import hashlib
    
    
    def is_pkcs7_padded(message):
        padding = message[-message[-1]:]
        return all(padding[i] == len(padding) for i in range(0, len(padding)))
    
    
    def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
        # Derive AES key from shared secret
        sha1 = hashlib.sha1()
        sha1.update(str(shared_secret).encode('ascii'))
        key = sha1.digest()[:16]
        # Decrypt flag
        ciphertext = bytes.fromhex(ciphertext)
        iv = bytes.fromhex(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
    
        if is_pkcs7_padded(plaintext):
            return unpad(plaintext, 16).decode('ascii')
        else:
            return plaintext.decode('ascii')
    
    
    shared_secret = 0
    iv = '2b8665e1f95f024bc4b8b40813f8c27b'
    ciphertext = '745cf18604b46a8dfee2cfd51ea58cb37ebca2d54623869528d1ab8d28328d99'
    
    print(decrypt_flag(shared_secret, iv, ciphertext))

>crypto{n1c3_0n3_m4ll0ry!!!!!!!!}
