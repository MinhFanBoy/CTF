from string import *
from requests import *

def get_requests(txt: str) -> str:
    plain_hex = txt.encode().hex()
    url = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + plain_hex
    r = get(url)
    r_data = r.json()
    return r_data.get("ciphertext", None)

def main():
    flag = ""

    alphabet = ascii_letters + digits + "{_/@#*}"

    while flag[-1:] != "}":
        for x in alphabet:
            
            flag_guess = flag + x
            guess = "A" * (16 - (len(flag_guess))% 16)
            padded = get_requests(guess + flag_guess + guess)
            point = 2 * ((16 - len(flag_guess)%16) + len(flag_guess))

            if padded[:point] == padded[point:point*2]:
                flag = flag + x
                print(x, end ="", flush=True)
                break

if __name__ == "__main__":
    main()