

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_8218998145909849489767589224752145194323996231101223014114062788439896662892324765430227087699807011312680357974547103427747626031176593986204926098978521 = Integer(8218998145909849489767589224752145194323996231101223014114062788439896662892324765430227087699807011312680357974547103427747626031176593986204926098978521); _sage_const_1860336365742538749239400340012599905091601221664081527583387276567734082070898348249407548568429668674672914754714801138206452116493106389151588267356258514501364109988967005351164279942136862087633991319071449095868845225164481135177941404709110974226338184970874613912364483762845606151111467768789248446875083250614540611690257121725792701375153027230580334095192816413366949340923355547691884448377941160689781707403607778943438589193122334667641037672649189861 = Integer(1860336365742538749239400340012599905091601221664081527583387276567734082070898348249407548568429668674672914754714801138206452116493106389151588267356258514501364109988967005351164279942136862087633991319071449095868845225164481135177941404709110974226338184970874613912364483762845606151111467768789248446875083250614540611690257121725792701375153027230580334095192816413366949340923355547691884448377941160689781707403607778943438589193122334667641037672649189861); _sage_const_65537 = Integer(65537); _sage_const_2 = Integer(2); _sage_const_1 = Integer(1); _sage_const_20 = Integer(20); _sage_const_0 = Integer(0); _sage_const_3 = Integer(3)
from tqdm import *
from Crypto.Util.number import *
from Crypto.Util.Padding import *
from Crypto.Cipher import AES
from hashlib import sha256
from math import gcd
from math import isqrt
from random import randrange

from sage.all import is_prime

n = _sage_const_8218998145909849489767589224752145194323996231101223014114062788439896662892324765430227087699807011312680357974547103427747626031176593986204926098978521 
c = b'\x9a \x8f\x96y-\xb4\tM\x1f\xe6\xcc\xef\xd5\x19\xf26`|B\x10N\xd7\xd0u\xafH\x8d&\xe3\xdbG\x13\x8e\xea\xc0N\n\r\x91\xdc\x95\x9b\xb1Ny\xc1\xc4'
hint = _sage_const_1860336365742538749239400340012599905091601221664081527583387276567734082070898348249407548568429668674672914754714801138206452116493106389151588267356258514501364109988967005351164279942136862087633991319071449095868845225164481135177941404709110974226338184970874613912364483762845606151111467768789248446875083250614540611690257121725792701375153027230580334095192816413366949340923355547691884448377941160689781707403607778943438589193122334667641037672649189861 
e = _sage_const_65537 
"""

hint = getPrime(20)*d**3 + getPrime(128)*phi**2

d = pow(e, -1, phi) -> e *d = 1 + k * phi

h * e ** 3 = a * (1 + k * phi) ** 3 + e ** 3 * b * phi ** 2
h * e ** 3 = a * (1 + 3 * (k * phi) ** 2 + 3 * k * phi + (k * phi) ** 3) + e ** 3 * b * phi ** 2

"""

def erato(n):

    arr = {}
    for i in range(_sage_const_2 , n):
        arr[i] = True

    for i in range(_sage_const_2 , ceil(sqrt(n))):
        if arr[i]:
            for j in range(i**_sage_const_2 , n, i):
                arr[j] = False

    return [i for i in trange(_sage_const_2 , n) if (arr[i] and int(i).bit_length() == (int(n).bit_length() - _sage_const_1 ))]

lst = erato(_sage_const_2  ** _sage_const_20 )

i = _sage_const_0 
for k in lst:
    tmp = pow(_sage_const_2 , hint * (e ** _sage_const_3 ) - k, n) - _sage_const_1 
    if not tmp:
        kphi = hint * (e ** _sage_const_3 ) - k

        p = gcd(pow(_sage_const_2 , kphi // (_sage_const_3  ** _sage_const_3 ), n) - _sage_const_1 , n)
        q = n // p
        key = sha256(str(p+q).encode()).digest()
        enc = AES.new(key, AES.MODE_ECB)
        print(enc.decrypt(c))
        exit()
