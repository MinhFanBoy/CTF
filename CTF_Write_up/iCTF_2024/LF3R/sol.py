import secrets, os
from tqdm import *
n = 256
MASK = 0x560074275752B31E43E64E99D996BC7B5A8A3DAC8B472FE3B83E6C6DDB5A26E7

x = [-3, -2, -1, 0, 1, 2, 3, 4]
y = [-3, -2, -1, 0, 1, 2, 3, 4]

state = 2 ** n - 1000

# for state in range(10000):
for x_ in range(-100, 100):
    # for y_ in y:
    if (state - x_) / 2 == (state - x_) // 2:
        
        tmp = (state >> 1) | (((state & MASK).bit_count() & 1) << (n - 1))
        k = (tmp - x_) // 2
        y = (state - k) / (2 ** (n - 1))
        # print(y)
        k = (tmp - x_) // 2 + y * 2 ** (n - 1)

        print(y, x_, state - k)
            # print(k, tmp)
            # if k == tmp:
            #     print(f"{state = }, {x_ = }, {y_ = }")

