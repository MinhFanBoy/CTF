
from pwn import *
from Crypto.Util.number import long_to_bytes
from sage.all import *
import itertools
from tqdm import *
# s = connect("35.187.238.100", 5001)

# s.recvuntil(b'"')
# prefix = str(s.recvuntil(b'"')[:-1].decode().strip())
# s.recvuntil(b'"')
# difficulty = len(str(s.recvuntil(b'"')[:-1].decode().strip()))

# p = process(['python3', 'solver_proof.py', prefix, str(difficulty)])

# output = p.recvline()[:-1].decode().strip()
# p.close()

# s.sendline(output)

s = process(['python3', 'chall.py'])
s.recvuntil(b"p = ")
p = int(s.recvline()[:-1].decode().strip())

index = []
lll = [[] for i in range(32)]
for i in range(1, 21):
    index += i*[i]
    lll[i].append(i)

for i in range(21, 26):
    index += [i]
    lll[1].append(i)

for idx, i in enumerate(range(26, 33)):
    index += (idx+2)*[i]
    lll[idx+2].append(i)

print(lll)
xs = ' '.join(map(str, index))
s.recvuntil(b"Gib me the queries: ")
s.sendline(xs)
s.recvuntil(b"shares = ")
shares = eval(s.recvline()[:-1].decode().strip())
# print(f"{shares = }")
# print(f"{p = }")

d = {_: shares.count(_) for _ in set(shares)}

tmp = [[] for i in range(32)]
for _, __ in d.items():
    tmp[__ - 1].append(_)

for i, j in enumerate(tmp):
    print(i, len(j))
x_9, x_10, x_11, x_12, x_13, x_14, x_15, x_16, x_17, x_18, x_19, x_20 = [_[0] for _ in tmp[8:20]]
for _ in tqdm(itertools.permutations(tmp[0])):
    x_1, x_21, x_22, x_23, x_24, x_25 = [l for l in _]
    for __ in itertools.permutations(tmp[1]):
        x_2, x_26 = __
        for ___ in itertools.permutations(tmp[2]):
            x_3, x_27 = ___
            for ____ in itertools.permutations(tmp[3]):
                x_4, x_28 = ____
                for _____ in itertools.permutations(tmp[4]):
                    x_5, x_29 = _____
                    for ______ in itertools.permutations(tmp[5]):
                        x_6, x_30 = ______
                        for _______ in itertools.permutations(tmp[6]):
                            x_7, x_31 = _______
                            for ________ in itertools.permutations(tmp[7]):
                                x_8, x_32 = ________
                            
                            
                                M = [
                                    [pow(i, tmp, p) for tmp in range(32)] for i in range(1, 33)
                                ]
                                M = matrix(Zmod(p), M)
                                X = column_matrix(Zmod(p), [x_1, x_2, x_3, x_4, x_5, x_6, x_7, x_8, x_9, x_10, x_11, x_12, x_13, x_14, x_15, x_16, x_17, x_18, x_19, x_20, x_21, x_22, x_23, x_24, x_25, x_26, x_27, x_28, x_29, x_30, x_31, x_32])
                                
                                tmp_ = M.solve_right(X)
                                for lmao in tmp_:
                                    xxx = long_to_bytes(int(lmao[0]))
                                    try:
                                        print(xxx.decode())
                                    except:
                                        pass
