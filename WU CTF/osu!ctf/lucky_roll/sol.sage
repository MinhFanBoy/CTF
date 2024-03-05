
from Crypto.Cipher import AES
load('https://gist.githubusercontent.com/Connor-McCartney/952583ecac836f843f50b785c7cb283d/raw/5718ebd8c9b4f9a549746094877a97e7796752eb/solvelinmod.py')

def get_roll():
    global seed
    seed = (a * seed + b) % p
    return seed % 100


p = 4420073644184861649599
a = 1144993629389611207194
b = 3504184699413397958941
out = [39, 47, 95, 1, 77, 89, 77, 70, 99, 23, 44, 38, 87, 34, 99, 42, 10, 67, 24, 3, 2, 80, 26, 87, 91, 86, 1, 71, 59, 97, 69, 31, 17, 91, 73, 78, 43, 18, 15, 46, 22, 68, 98, 60, 98, 17, 53, 13, 6, 13, 19, 50, 73, 44, 7, 44, 3, 5, 80, 26, 10, 55, 27, 47, 72, 80, 53, 2, 40, 64, 55, 6]
enc = bytes.fromhex('34daaa9f7773d7ea4d5f96ef3dab1bbf5584ecec9f0542bbee0c92130721d925f40b175e50587196874e14332460257b')

xx = [var(f"x_{i}") for i in range(72)]
bounds = {x : 2 ^ 65 for x in xx}

s = var("s")

bounds[s] = p

equations = []

for i, x in enumerate(xx):
    s = (a * s + b)
    equations.append((s == x * 100 + out[i], p))

seed = solve_linear_mod(equations, bounds)[var("s")]
for i in range(72):
    get_roll()
key = bytes([get_roll() for _ in range(16)])
iv = bytes([get_roll() for _ in range(16)])
cipher = AES.new(key, AES.MODE_CBC, iv)
print(cipher.decrypt(enc))