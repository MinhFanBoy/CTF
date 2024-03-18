
import time
import random
from pwn import xor
import datetime

correct = [192, 123, 40, 205, 152, 229, 188, 64, 42, 166, 126, 125, 13, 187, 91]

start = datetime.datetime(2023, 12, 31, 0, 0, 0, tzinfo=datetime.timezone.utc)
end = datetime.datetime(2024, 1, 2, 0, 0, 0, tzinfo=datetime.timezone.utc)

# for second in range(int(start.timestamp()), int(end.timestamp())):
#     random.seed(second)
#     if (192 ^ random.getrandbits(8) == ord("w")):
#         print(second)
#         break
t = 1704153599
h = 0
for i in range(len(correct)):
    
    random.seed(i+t + h)
    print(chr(correct[i] ^ random.getrandbits(8)), end = "", flush= True)
    h += random.randint(1, 60)

    
