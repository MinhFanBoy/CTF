
from pwn import *
from base64 import b64encode, b64decode
from string import ascii_lowercase, ascii_uppercase, digits
from tqdm import tqdm
context.log_level = "debug"
s = remote("tamuctf.com", 443, ssl=True, sni="criminal")

alphabet = ascii_lowercase + ascii_uppercase + digits + "_{}"

solution = "gigem{"

while "}" not in solution:
    best = ""
    best_length = 999

    for c in tqdm(range(len(alphabet))):
        # try:
            s.sendlineafter(b"Append whatever you want to the flag: ", solution + alphabet[c])
            res = b64decode(s.recvline().strip())
            print(res)
            nonce = res[:12]
            enc = res[12: -16]
            if len(enc) < best_length:
                best = alphabet[c]
                best_length = len(enc)
        # except:

        #     s = remote("tamuctf.com", 443)
    solution += best

print(solution)

