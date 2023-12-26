
import hashlib
from string import *
from pwn import xor
from Crypto.Util.number import *

enc = open("enc_msg_fixed.txt", "rb")
txt = enc.read()
e = 65537
n = 20675528040670526996752940893288629654073674678976458593562885254372323957903532876778575683971980608430988271483012687068546409103618011471627912308716870404710200387846081948584012645579489130659361868569525868828863142513688732813453572263121568340255562594977295513766156580889393986895191199436845252360294885224181350174035317346113446210888214332389015986819447524673296950196284975878585211748477505072532061859389809017849787533731620947172314201145532242513117285325664785809436379731158841381092296256976553945301076520532403729003821419792192809111636400447743715443579056636708987896016462504011033448823
def dbytes2int(b): 
    return b[0]*256+b[1] 

def f(test):

    ciphertxt = b''
    for i in range(0, len(test), 2): 
        plt = dbytes2int(test[i:i+2])
        c = pow(plt,e,n)
        # print(c) 
        h = hashlib.sha256(long_to_bytes(c)).hexdigest()
        k = bytes.fromhex(h[:8])
        # print(h)
        ciphertxt += k
    return ciphertxt

alphabet = "!@#$%^&*()_+{|>?<}:-=[],./?" + digits + ascii_lowercase + ascii_uppercase 
flag = "KCSC"

while "}" not in flag:
    for x in range(len(alphabet)):
        for y in range(len(alphabet)):
            flag_guess = flag + alphabet[x] + alphabet[y]
            d = bytes(flag_guess.encode("utf-8"))
            if f(d) in txt:
                flag = flag_guess
                print(flag)
                break


