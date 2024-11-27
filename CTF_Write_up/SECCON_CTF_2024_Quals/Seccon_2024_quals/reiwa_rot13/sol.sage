
import logging 
import sys
from Crypto.Util.number import *
from tqdm import trange
import hashlib
from Crypto.Cipher import AES

sys.setrecursionlimit(500000)

def HGCD(a, b):
    if 2 * b.degree() <= a.degree() or a.degree() == 1:
        return 1, 0, 0, 1
    m = a.degree() // 2
    a_top, a_bot = a.quo_rem(x^m)
    b_top, b_bot = b.quo_rem(x^m)
    R00, R01, R10, R11 = HGCD(a_top, b_top)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    q, e = c.quo_rem(d)
    d_top, d_bot = d.quo_rem(x^(m // 2))
    e_top, e_bot = e.quo_rem(x^(m // 2))
    S00, S01, S10, S11 = HGCD(d_top, e_top)
    RET00 = S01 * R00 + (S00 - q * S01) * R10
    RET01 = S01 * R01 + (S00 - q * S01) * R11
    RET10 = S11 * R00 + (S10 - q * S11) * R10
    RET11 = S11 * R01 + (S10 - q * S11) * R11
    return RET00, RET01, RET10, RET11
    
def GCD(a, b):

    q, r = a.quo_rem(b)
    if r == 0:
        return b
    R00, R01, R10, R11 = HGCD(a, b)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    if d == 0:
        return c.monic()
    q, r = c.quo_rem(d)
    if r == 0:
        return d
    return GCD(d, r)

n = 105270965659728963158005445847489568338624133794432049687688451306125971661031124713900002127418051522303660944175125387034394970179832138699578691141567745433869339567075081508781037210053642143165403433797282755555668756795483577896703080883972479419729546081868838801222887486792028810888791562604036658927
e = 137
c1 = 16725879353360743225730316963034204726319861040005120594887234855326369831320755783193769090051590949825166249781272646922803585636193915974651774390260491016720214140633640783231543045598365485211028668510203305809438787364463227009966174262553328694926283315238194084123468757122106412580182773221207234679
c2 = 54707765286024193032187360617061494734604811486186903189763791054142827180860557148652470696909890077875431762633703093692649645204708548602818564932535214931099060428833400560189627416590019522535730804324469881327808667775412214400027813470331712844449900828912439270590227229668374597433444897899112329233
encyprted_flag =  b"\xdb'\x0bL\x0f\xca\x16\xf5\x17>\xad\xfc\xe2\x10$(DVsDS~\xd3v\xe2\x86T\xb1{xL\xe53s\x90\x14\xfd\xe7\xdb\xddf\x1fx\xa3\xfc3\xcb\xb5~\x01\x9c\x91w\xa6\x03\x80&\xdb\x19xu\xedh\xe4"

cacl = lambda x: sum(i * (256 ** j) for j, i in enumerate(x[::-1]))

R.<x> = PolynomialRing(Zmod(n))


for i in trange(0, 1 << 10):
    diff = list(map(int, bin(i)[2:].zfill(10)))
    diff = [13 if i == 1 else -13 for i in diff]
    w = cacl(diff)
    g = (x) ^ e - c1
    PR.<y> = R.quotient(g)
    h = (y + w)^e - c2
    f = h.lift()
    key = long_to_bytes(int(-GCD(g, f).change_ring(Zmod(n)).monic().coefficients()[0] % n))
    
    if len(key) == 10:
        key = hashlib.sha256(key).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        print(cipher.decrypt(encyprted_flag))
