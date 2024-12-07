
### crypto/Twister

**__deploy.py__**

```py
from dataclasses import dataclass
from cmath import exp
import secrets
import time
import os

FLAG = os.getenv("FLAG") or "test{flag_for_local_testing}"


@dataclass
class Wave:
    a: int
    b: int

    def eval(self, x):
        theta = x / self.a + self.b
        return ((exp(1j * theta) - exp(-1j * theta)) / 2j).real

ALL_WAVES = [Wave(a, b) for a in range(2, 32) for b in range(7)]
secret = [secrets.randbits(1) for _ in ALL_WAVES]
class MaximTwister:
    """
    Next-generation PRNG with really **complex** nature.
    More reliable than /dev/random cuz doesn't block ever.
    """

    def __init__(self, state=None):
        if state is None:
            state = (1337, [secrets.randbits(1) for _ in ALL_WAVES])

        self.point = state[0]
        self.waves = [wave for wave, mask in zip(ALL_WAVES, state[1]) if mask]

    def get_randbit(self) -> int:
        result = 0
        for wave in self.waves:
            # you would never decompose a sum of waves 😈
            result += round(wave.eval(self.point))
        # especially if you know only the remainder, right? give up
        result %= 2
        self.point += 1

        return result

    def get_randbits(self, k: int) -> int:
        return int("".join(str(self.get_randbit()) for _ in range(k)), 2)

    def get_token_bytes(self, k: int) -> bytes:
        return bytes([self.get_randbits(8) for _ in range(k)])


print("*** BUG DESTROYER ***")
print("You encounter: 😈 SEGMENTATION FAULT 😈")
opponent_hp = int(time.time()) * 123
days_passed = 0

random = MaximTwister((1337, secret))

while True:
    print(
        f"🕺 You ({10-days_passed} days till release) -- 😈 SEGMENTATION FAULT ({opponent_hp} lines)"
    )
    print(f"Day {days_passed + 1}. You can:")
    print("1. Make a fix")
    print("2. Call a senior")
    choice = input("> ").strip()
    if choice == "1":
        damage = random.get_randbits(32)
        opponent_hp -= damage
        if opponent_hp <= 0:
            print(
                f"You commited a fix deleting {damage} lines. Miraculously, it worked!"
            )
            break
        else:
            print(f"You commited a fix deleting {damage} lines. The bug remained 😿")
    elif choice == "2":
        print("You called a senior. It's super effective! The bug is destroyed.")
        break
    else:
        print(
            f"You spent {random.get_randbits(4)} hours doing whatever {choice} means."
        )

    print("A day has passed. You couldn't fix the bug.")
    days_passed += 1

    if days_passed == 10:
        print("It's release date! The bug is still there. You're fired.")
        exit()

print("The bug is gone! You got a raise.")
print(
    "In your new office you see a strange door. It is locked. You try to guess the password from the digital lock:"
)
password = input("> ")
k = random.get_token_bytes(16)
if bytes.fromhex(password) == k:
    print("Somehow, you guessed the password! The room opens before you.")
    print("You see a mysterious text:", FLAG)
    print(
        "What could it mean?... You turn around and see your boss right behind you..."
    )
    print("BAD ENDING")
else:
    print("Incorrect. Well, let's get back to work...")
    print("GOOD ENDING")
    print(k)
    print(secret)
```

#### 1. Solution

+ Chúng ta có thể tóm gọn lại code như sau:

    + Ta có tổng cộng `9 * 32` bit của hàm `get_randbits` thuộc class `MaximTwister` và ta phải tìm được 16 bytes tiếp theo.
    + class `Wave` chứa hàm `eval` để tính phần thực của $(e^{i * (x / a + b)} - e^{-i * (x / a + b)}) / (2 * i)$. Mình có tìm cách rút gọn lại biểu thức thì thấy nó có thể tương đương với $f(a, b, x) = sin(x / a + b)$

Thấy `ALL_WAVES = [Wave(a, b) for a in range(2, 32) for b in range(7)]`, `secret = [secrets.randbits(1) for _ in ALL_WAVES]` khi đó chương trình tính tất cả các wave ra rồi chọn ngẫu nhiên random những wave đó để tính.

Ta có 
```py
    def __init__(self, state=None):
        if state is None:
            state = (1337, [secrets.randbits(1) for _ in ALL_WAVES])

        self.point = state[0]
        self.waves = [wave for wave, mask in zip(ALL_WAVES, state[1]) if mask]

    def get_randbit(self) -> int:
        result = 0
        for wave in self.waves:
            # you would never decompose a sum of waves 😈
            result += round(wave.eval(self.point))
        # especially if you know only the remainder, right? give up
        result %= 2
        self.point += 1

        return result
```

trong chương trình được chạy state không được truyền vào nên seed mặc đinh là 1337 và các wave vẫn được tính ngẫu nhiên. Để lấy được một bit random thì chương trình chạy lấy tổng tất cả các giá trị tính được hàm eval rồi mod 2. Do hàm eval là hàm sin mà trong trường hợp này giá trị đã được làm tròn nên nó sẽ có thể có 3 giá trị là -1, 0, 1. Nhưng do bị mod 2 ở cuối nên ta có thể gộp lại thành 2 trường hợp là 0, 1.

vậy ${result} = \sum_{i = 0}^{len(all_waves)}{{secret_{i}} * f(a, b, seed)}$

dễ thấy đây là quan hệ tuyến tính của $f(a, b, seed)$ và $result$ mà ta đã biết cả hai cái này nên có thể dễ dàng dựng ma trận để tìm lại secret.

#### 2. Code

```py

func = lambda a, b, x: RR(sin(x / a + b))
def matrix_overview(BB):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            if BB[ii, jj] == 0:
                a += ' '
            elif BB[ii, jj] == 1:
                a += '1'
            elif BB[ii, jj] == -1:
                a += '-'
            else:
                a += 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        print(a)
from dataclasses import dataclass
from cmath import exp
import secrets
import time
import os
from tqdm import *

@dataclass
class Wave:
    a: int
    b: int

    def eval(self, x):
        return func(self.a, self.b, x)
    

import os

set_verbose(0)
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'linux'

from pwn import *

# context.log_level = 'debug'
# s = process(['python3', 'deploy.py'])
s = connect("twister.chal.wwctf.com", 1337)
l = []
for i in range(9):
    
    s.sendlineafter(">", str(1))
    s.recvuntil(b' You commited a fix deleting ')
    k = bin(int(s.recvuntil(b" ").strip()))[2:].zfill(32)
    for i in k:
        l.append(int(i))
    s.recvline()

# s.interactive()

ALL_WAVES = [Wave(a, b) for a in range(2, 32) for b in range(7)]
state = (1337, [1 for _ in ALL_WAVES])
point = state[0]
waves = [wave for wave, mask in zip(ALL_WAVES, state[1]) if mask]
q = 2
n = len(l)
L = [[] for i in range(n)]

for i in trange(n):

    for wave in waves:
        k = round(wave.eval(point + i))
        L[i].append(k)

M = matrix(GF(2), L)
V = vector(GF(2), l)

k = M.solve_right(V)
print(len(k.list()))
class MaximTwister:
    """
    Next-generation PRNG with really **complex** nature.
    More reliable than /dev/random cuz doesn't block ever.
    """

    def __init__(self, state=None):
        if state is None:
            state = (1337, k)

        self.point = state[0]
        self.waves = [wave for wave, mask in zip(ALL_WAVES, state[1]) if mask]

    def get_randbit(self) -> int:
        result = 0
        for wave in self.waves:
            # you would never decompose a sum of waves 😈
            result += round(wave.eval(self.point))
        # especially if you know only the remainder, right? give up
        result %= 2
        self.point += 1

        return result

    def get_randbits(self, k: int) -> int:
        return int("".join(str(self.get_randbit()) for _ in range(k)), 2)

    def get_token_bytes(self, k: int) -> bytes:
        return bytes([self.get_randbits(8) for _ in range(k)])

random = MaximTwister((1337, list(k)))
for i in range(9):
    random.get_randbits(32)

s.sendlineafter(">", str(2))
s.recvline()
x = random.get_token_bytes(16)
s.sendlineafter(">", x.hex())

s.interactive()
```
