

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_500000 = Integer(500000); _sage_const_2 = Integer(2); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_128134155200900363557361770121648236747559663738591418041443861545561451885335858854359771414605640612993903005548718875328893717909535447866152704351924465716196738696788273375424835753379386427253243854791810104120869379525507986270383750499650286106684249027984675067236382543612917882024145261815608895379 = Integer(128134155200900363557361770121648236747559663738591418041443861545561451885335858854359771414605640612993903005548718875328893717909535447866152704351924465716196738696788273375424835753379386427253243854791810104120869379525507986270383750499650286106684249027984675067236382543612917882024145261815608895379); _sage_const_5331 = Integer(5331); _sage_const_60668946079423190709851484247433853783238381043211713258950336572392573192737047470465310272448083514859509629066647300714425946282732774440406261265802652068183263460022257056016974572472905555413226634497579807277440653563498768557112618320828785438180460624890479311538368514262550081582173264168580537990 = Integer(60668946079423190709851484247433853783238381043211713258950336572392573192737047470465310272448083514859509629066647300714425946282732774440406261265802652068183263460022257056016974572472905555413226634497579807277440653563498768557112618320828785438180460624890479311538368514262550081582173264168580537990); _sage_const_43064371535146610786202813736674368618250034274768737857627872777051745883780468417199551751374395264039179171708712686651485125338422911633961121202567788447108712022481564453759980969777219700870458940189456782517037780321026907310930696608923940135664565796997158295530735831680955376342697203313901005151 = Integer(43064371535146610786202813736674368618250034274768737857627872777051745883780468417199551751374395264039179171708712686651485125338422911633961121202567788447108712022481564453759980969777219700870458940189456782517037780321026907310930696608923940135664565796997158295530735831680955376342697203313901005151)
from Crypto.Util.number import *
import logging 
import sys

sys.setrecursionlimit(_sage_const_500000 )

def HGCD(a, b):
    if _sage_const_2  * b.degree() <= a.degree() or a.degree() == _sage_const_1 :
        return _sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 
    m = a.degree() // _sage_const_2 
    a_top, a_bot = a.quo_rem(x**m)
    b_top, b_bot = b.quo_rem(x**m)
    R00, R01, R10, R11 = HGCD(a_top, b_top)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    q, e = c.quo_rem(d)
    d_top, d_bot = d.quo_rem(x**(m // _sage_const_2 ))
    e_top, e_bot = e.quo_rem(x**(m // _sage_const_2 ))
    S00, S01, S10, S11 = HGCD(d_top, e_top)
    RET00 = S01 * R00 + (S00 - q * S01) * R10
    RET01 = S01 * R01 + (S00 - q * S01) * R11
    RET10 = S11 * R00 + (S10 - q * S11) * R10
    RET11 = S11 * R01 + (S10 - q * S11) * R11
    return RET00, RET01, RET10, RET11
    
def GCD(a, b):
    print(f"._. --> : d_a = {a.degree()}, d_b = {b.degree()}")

    q, r = a.quo_rem(b)
    if r == _sage_const_0 :
        return b
    R00, R01, R10, R11 = HGCD(a, b)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    if d == _sage_const_0 :
        return c.monic()
    q, r = c.quo_rem(d)
    if r == _sage_const_0 :
        return d
    return GCD(d, r)

n = _sage_const_128134155200900363557361770121648236747559663738591418041443861545561451885335858854359771414605640612993903005548718875328893717909535447866152704351924465716196738696788273375424835753379386427253243854791810104120869379525507986270383750499650286106684249027984675067236382543612917882024145261815608895379 
e = _sage_const_5331 
c1 = _sage_const_60668946079423190709851484247433853783238381043211713258950336572392573192737047470465310272448083514859509629066647300714425946282732774440406261265802652068183263460022257056016974572472905555413226634497579807277440653563498768557112618320828785438180460624890479311538368514262550081582173264168580537990 
c2 = _sage_const_43064371535146610786202813736674368618250034274768737857627872777051745883780468417199551751374395264039179171708712686651485125338422911633961121202567788447108712022481564453759980969777219700870458940189456782517037780321026907310930696608923940135664565796997158295530735831680955376342697203313901005151 

R = PolynomialRing(Zmod(n), names=('x',)); (x,) = R._first_ngens(1)
g = (_sage_const_2  * x + _sage_const_1 ) ** e - c1
PR = R.quotient(g, names=('y',)); (y,) = PR._first_ngens(1)
print(PR)
h = y**e - c2
f = h.lift()

res = GCD(f,g).monic().coefficients()[_sage_const_0 ]
print(long_to_bytes(int(_sage_const_2  * int(-res % n) + _sage_const_1 )))
