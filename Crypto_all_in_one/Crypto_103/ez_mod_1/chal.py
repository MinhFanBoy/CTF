from Crypto.Util.number import *
from random import *

table = "01234567"
p = getPrime(328)
flag = b"NSSCTF{" + "".join([choice(table) for i in range(80)]).encode() + b"}"
c = bytes_to_long(flag) % p

print("p =",p)
print("c =",c)
print(flag)

'''
p = 324556397741108806830285502585098109678766437252172614832253074632331911859471735318636292671562523
c = 141624663734155235543198856069652171779130720945875442624943917912062658275440028763836569215230250
'''
