import random
import os

flag = os.getenv("FLAG") or "FLAG{test_flag}"


def main():
    random.seed(os.urandom(32))
    Hint = b"".join(
        [
            (random.getrandbits(32) & 0x44417A9F).to_bytes(4, byteorder="big")
            for i in range(2000)
        ]
    )
    Secret = random.randbytes(len(flag))
    print(Secret.hex(), file=__import__("sys").stderr)
    Encrypted = [(ord(x) ^ y) for x, y in zip(flag, Secret)]
    random.shuffle(Encrypted)

    print(f"Hint: {Hint.hex()}")
    print(f"Encrypted flag: {bytes(Encrypted).hex()}")


if __name__ == "__main__":
    main()
