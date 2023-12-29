
import string
import random
 
table = string.printable[:-3]

f = lambda x : (a*x + b) % len(table)
d = lambda x : (pow(a, -1, len(table)) * (x - b)) % len(table)

def encryption(plaintext):
    ciphertext = ''
    for char in plaintext :
        i = table.index(char)
        c = table[f(i)]
        ciphertext+=c
    return ciphertext
 
def decryption(enc: str) -> str:
    flag = ""
    for x in enc:
        i = table.index(x)
        p = table[d(i)]
        flag += p
    return flag

flag = 'KCSC{????????????????????????????????????????????}'
 
# print(encryption(flag))
 

ciphertext  = '.^"^9{,, Z|c^ Wv|gc 5c_Lc|w_~cm)wWc+bZc+wQc+wcvbt6'

while True:
    try:
            
        a = random.randint(1,len(table))
        b = random.randint(0,len(table))
        
        t = decryption(ciphertext)
        print(t)
        if "KCSC" in t:
            print(t)
            break
    except:
        pass
