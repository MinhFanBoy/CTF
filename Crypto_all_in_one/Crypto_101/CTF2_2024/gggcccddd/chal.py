from Crypto.Util.number import *
from enc import flag

m = bytes_to_long(flag)

p = getPrime(512)
q = getPrime(512)
n = p*q
e = 65537
c1 = pow(m,e,n)
c2 = pow(233*m+9527,e,n)
print(f'n = {n}')
print(f'c1 = {c1}')
print(f'c2 = {c2}')
print(f'e = {e}')
"""
n = 71451784354488078832557440841067139887532820867160946146462765529262021756492415597759437645000198746438846066445835108438656317936511838198860210224738728502558420706947533544863428802654736970469313030584334133519644746498781461927762736769115933249195917207059297145965502955615599481575507738939188415191
c1 = 60237305053182363686066000860755970543119549460585763366760183023969060529797821398451174145816154329258405143693872729068255155086734217883658806494371105889752598709446068159151166250635558774937924668506271624373871952982906459509904548833567117402267826477728367928385137857800256270428537882088110496684
c2 = 20563562448902136824882636468952895180253983449339226954738399163341332272571882209784996486250189912121870946577915881638415484043534161071782387358993712918678787398065688999810734189213904693514519594955522460151769479515323049821940285408228055771349670919587560952548876796252634104926367078177733076253
e = 65537
"""