
def de_vigenere(flag: str, key: str) -> str:

    alphabet = ascii_uppercase
  # nho thay doi alphabet !
    txt = ""
  
    for x in range(len(flag)):
        tmp = alphabet.index(flag[x]) - alphabet.index(key[x % len(key)])

        txt += alphabet[tmp % len(alphabet)]
    
    return txt
