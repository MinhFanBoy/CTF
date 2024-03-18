import time
import random
from Crypto.Util.number import long_to_bytes

def main() -> None:
    
    correct = [189, 24, 103, 164, 36, 233, 227, 172, 244, 213, 61, 62, 84, 124, 242, 100, 22, 94, 108, 230, 24, 190, 23, 228, 24]
    flag_form = "wctf{"


    for j in range(256):

        flag = b""
        for i in range(len(correct)):
            random.seed(i+j)
            flag += long_to_bytes(correct[i] ^ random.getrandbits(8))
        print(f"{flag = }")


if __name__ == "__main__":
    main()