from Crypto.Util.number import *
from secret import flag

def padding(flag):
    return flag+b'\xff'*(64-len(flag))

flag=padding(flag)
m=bytes_to_long(flag)
p=getPrime(512)
q=getPrime(512)
e=3
n=p*q
c=pow(m,e,n)
m0=m>>208

print(f'n={n}')
print(f'c={c}')
print(f'm0={m0}')

"""
n=120838778421252867808799302603972821425274682456261749029016472234934876266617266346399909705742862458970575637664059189613618956880430078774892479256301209695323302787221508556481196281420676074116272495278097275927604857336484564777404497914572606299810384987412594844071935546690819906920254004045391585427
c=118961547254465282603128910126369011072248057317653811110746611348016137361383017921465395766977129601435508590006599755740818071303929227578504412967513468921191689357367045286190040251695094706564443721393216185563727951256414649625597950957960429709583109707961019498084511008637686004730015209939219983527
m0=13292147408567087351580732082961640130543313742210409432471625281702327748963274496942276607
"""