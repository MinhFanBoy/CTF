import datetime
import random

enc = [192, 123, 40, 205, 152, 229, 188, 64, 42, 166, 126, 125, 13, 187, 91]

# year = 2023,
# tm_yday = 365 or 366
# gmt
# start = datetime.datetime(2023, 12, 31, 0, 0, 0, tzinfo=datetime.timezone.utc)
# end = datetime.datetime(2024, 1, 2, 0, 0, 0, tzinfo=datetime.timezone.utc)

# for second in range(int(start.timestamp()), int(end.timestamp())):
#     random.seed(second)
#     if enc[0] ^ random.getrandbits(8) == b'w'[0]:
#         v_ = second + random.randint(1, 60)
#         random.seed(v_ + 1)
#         if enc[1] ^ random.getrandbits(8) == b'c'[0]:
#             v_ = v_ + random.randint(1, 60)
#             random.seed(v_ + 2)
#             if enc[2] ^ random.getrandbits(8) == b't'[0]:
#                 print(second)
#                 v_ = v_ + random.randint(1, 60)
#                 random.seed(v_ + 3)
#                 if enc[3] ^ random.getrandbits(8) == b'f'[0]:
#                     print(second)

second = 1704153599
flag = b''
for i in range(len(enc)):
    random.seed(second + i)
    flag += bytes([enc[i] ^ random.getrandbits(8)])
    second += random.randint(1, 60)

print(flag)