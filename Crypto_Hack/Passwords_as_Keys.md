# crypto

---

**_Description:_**
It is essential that keys in symmetric-key algorithms are random bytes, instead of passwords or other predictable data. The random bytes should be generated using a cryptographically-secure pseudorandom number generator (CSPRNG). If the keys are predictable in any way, then the security level of the cipher is reduced and it may be possible for an attacker who gets access to the ciphertext to decrypt it.

Just because a key looks like it is formed of random bytes, does not mean that it necessarily is. In this case the key has been derived from a simple password using a hashing function, which makes the ciphertext crackable.

Play at [here](https://aes.cryptohack.org/passwords_as_keys)

---

In link, we have enc_flag is {"ciphertext":"c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"} and know key is in [here](https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
). So i will download and save it as learn.txt. Try brutce force string in learn.txt, will find key.

        from Crypto.Cipher import AES
        import hashlib
        
        from binascii import *
        
        
        # /usr/share/dict/words from
        # https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
        with open("learn.txt", "r+") as f:
            words = [w.strip() for w in f.readlines()]
        
        def decrypt(ciphertext, password_hash):
            ciphertext = bytes.fromhex(ciphertext)
            key = bytes.fromhex(password_hash)
        
            cipher = AES.new(key, AES.MODE_ECB)
            try:
                decrypted = cipher.decrypt(ciphertext)
            except ValueError as e:
                return {"error": str(e)}
        
            return decrypted
        
        for keyword in words:
            KEY = hashlib.md5(keyword.encode()).digest()
            KEY = KEY.hex()
            flag = decrypt("c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66", KEY)
            if b'crypto' in flag:
                print(flag)
                break
            else:
                print(flag)
