from random import randint
from re import search

flag = b"KMACTF{fake_flag}"
flag = flag[7: -1]

p = random_prime(2**1024)
setup = [randint(0, 2**32) for _ in range(len(flag))]
setup = [f ^^ ((pad >> 8) << 8) for f, pad in zip(flag, setup)]

output = []

for _ in range(len(flag)^2):
    noise1 = [randint(0, 2**32) for _ in range(1000)]
    noise2 = [randint(0, len(setup)-1) for _ in range(1000)]
    noise3 = [randint(0, len(setup)-1) for _ in range(1000)]
    noise4 = [randint(0, 2**32) for _ in range(1000)]
    noise5 = [randint(0, 2**32) for _ in range(1000)]


    output.append(noise1)
    output.append(noise2)
    output.append(noise3)
    output.append(noise4)
    output.append(noise5)

    s = 0
    for i in range(1000):
        s += (noise5[i] * (noise1[i] + pow(setup[noise2[i]], 1337, p) * pow(setup[noise3[i]], 1663, p)) + noise4[i]) % p

    output.append(s % p)

f = open("out.txt", "w")
f.write(f"{p = }\n")
f.write(f"{output = }\n")