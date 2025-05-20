from pk import pk
from PermEG import encrypt

if __name__ == "__main__":
    m = input("Enter the message you want to encrypt here: ")
    result = encrypt(pk, m.encode("utf-8"))
    with open("out.txt", "w") as f:
        f.write(str(result))
    print("Ciphertext written to out.txt")