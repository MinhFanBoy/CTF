from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import sympy as sp

array = [[0, 14], [2, 12], [2, 14], [4, 10], [4, 14], [6, 8], [6, 10], [6, 12], [6, 14], [8, 6], [8, 14], [10, 4], [10, 6], [10, 12], [10, 14], [12, 2], [12, 6], [12, 10], [12, 14], [14, 0], [14, 2], [14, 4], [14, 6], [14, 8], [14, 10], [14, 12], [14, 14]]

x = sp.symbols('x')

C1, C2 = sp.symbols('C1 C2')

f = C1 * sp.exp((3 + sp.sqrt(3))/2 * x) + C2 * sp.exp((3 - sp.sqrt(3))/2 * x)
f_prime = sp.diff(f, x)
f_second_prime = sp.diff(f_prime, x)
for a, b in array:
    try:

        init_cond_1 = f.subs(x, 0) -a
        init_cond_2 = f_prime.subs(x, 0)- b
        sol = sp.solve([init_cond_1, init_cond_2], (C1, C2))

        f = f.subs(sol)

        f_prime = sp.diff(f, x)
        f_second_prime = sp.diff(f_prime, x)

        assert(2*f_second_prime - 6*f_prime + 3*f == 0)
        assert(f.subs(x, 0) | f_prime.subs(x, 0) == 14)

        def decrypt(encrypted, key):
            encrypted_bytes = bytes.fromhex(encrypted)
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]
            
            point = f.subs(x, key).evalf(100)
            
            point_hash = hashlib.sha256(str(point).encode()).digest()[:16]
            
            cipher = AES.new(point_hash, AES.MODE_CBC, iv)
            decrypted_message = cipher.decrypt(ciphertext)
            
            return decrypted_message

        key = 60
        encrypted = "805534c14e694348a67da0d75165623cf603c2a98405b34fe3ba8752ce24f5040c39873ec2150a61591b233490449b8b7bedaf83aa9d4b57d6469cd3f78fdf55"

        flag = decrypt(encrypted, key)

        print(f"Flag: {flag}")

    except:
        pass