

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_65537 = Integer(65537); _sage_const_23145761572719481962762273155673006162798724771853359777738044204075205506442533110957905454673168677138390288946164925146182350082798412822843805544411533748092944111577005586562560198883223125408349637392132331590745338744632420471550117436081738053152425051777196723492578868061454261995047266710226954140246577840642938899700421187651113304598644654895965391847939886431779910020514811403672972939220544348355199254228516702386597854501038639792622830084538278039854948584633614251281566284373340450838609257716124253976669362880920166668588411500606044047589369585384869618488029661584962261850614005626269748136 = Integer(23145761572719481962762273155673006162798724771853359777738044204075205506442533110957905454673168677138390288946164925146182350082798412822843805544411533748092944111577005586562560198883223125408349637392132331590745338744632420471550117436081738053152425051777196723492578868061454261995047266710226954140246577840642938899700421187651113304598644654895965391847939886431779910020514811403672972939220544348355199254228516702386597854501038639792622830084538278039854948584633614251281566284373340450838609257716124253976669362880920166668588411500606044047589369585384869618488029661584962261850614005626269748136); _sage_const_21293043264185301689671141081477381397341096454508291834869907694578437286574195450398858995081655892976217341587431170279280993193619462282509529429783481444479483042173879669051228851679105028954444823160427758701176787431760859579559910604299900563680491964215291720468360933456681005593307187729279478018539532102837247060040450789168837047742882484655150731188613373706854145363872001885815654186972492841075619196485090216542847074922791386068648687399184582403554320117303153178588095463812872354300214532980928150374681897550358290689615020883772588218387143725124660254095748926982159934321361143271090861833 = Integer(21293043264185301689671141081477381397341096454508291834869907694578437286574195450398858995081655892976217341587431170279280993193619462282509529429783481444479483042173879669051228851679105028954444823160427758701176787431760859579559910604299900563680491964215291720468360933456681005593307187729279478018539532102837247060040450789168837047742882484655150731188613373706854145363872001885815654186972492841075619196485090216542847074922791386068648687399184582403554320117303153178588095463812872354300214532980928150374681897550358290689615020883772588218387143725124660254095748926982159934321361143271090861833); _sage_const_309575642078438773208947649750793560438038690144069550000470706236111082406 = Integer(309575642078438773208947649750793560438038690144069550000470706236111082406); _sage_const_303394719183577651416751448350927044928060280972644968966068528268042222965 = Integer(303394719183577651416751448350927044928060280972644968966068528268042222965); _sage_const_4597063839057338886607228486569583368669829061896475991448013970518668754752831268343529061846220181652766402988715484221563478749446497476462877699249731 = Integer(4597063839057338886607228486569583368669829061896475991448013970518668754752831268343529061846220181652766402988715484221563478749446497476462877699249731); _sage_const_3253873276452081483545152055347615580632252871708666807881332670645532929747667442194685757039215506084199053032613562932819745309368748317106660561209205 = Integer(3253873276452081483545152055347615580632252871708666807881332670645532929747667442194685757039215506084199053032613562932819745309368748317106660561209205); _sage_const_0 = Integer(0); _sage_const_1000 = Integer(1000); _sage_const_256 = Integer(256); _sage_const_1 = Integer(1)
from Crypto.Util.number import *
from tqdm import *
from gmpy2 import *

e = _sage_const_65537 

m1 = _sage_const_23145761572719481962762273155673006162798724771853359777738044204075205506442533110957905454673168677138390288946164925146182350082798412822843805544411533748092944111577005586562560198883223125408349637392132331590745338744632420471550117436081738053152425051777196723492578868061454261995047266710226954140246577840642938899700421187651113304598644654895965391847939886431779910020514811403672972939220544348355199254228516702386597854501038639792622830084538278039854948584633614251281566284373340450838609257716124253976669362880920166668588411500606044047589369585384869618488029661584962261850614005626269748136 
m2 = _sage_const_21293043264185301689671141081477381397341096454508291834869907694578437286574195450398858995081655892976217341587431170279280993193619462282509529429783481444479483042173879669051228851679105028954444823160427758701176787431760859579559910604299900563680491964215291720468360933456681005593307187729279478018539532102837247060040450789168837047742882484655150731188613373706854145363872001885815654186972492841075619196485090216542847074922791386068648687399184582403554320117303153178588095463812872354300214532980928150374681897550358290689615020883772588218387143725124660254095748926982159934321361143271090861833 
sum1 = _sage_const_309575642078438773208947649750793560438038690144069550000470706236111082406 
sum2 = _sage_const_303394719183577651416751448350927044928060280972644968966068528268042222965 
n = _sage_const_4597063839057338886607228486569583368669829061896475991448013970518668754752831268343529061846220181652766402988715484221563478749446497476462877699249731 
c = _sage_const_3253873276452081483545152055347615580632252871708666807881332670645532929747667442194685757039215506084199053032613562932819745309368748317106660561209205 

for i1 in trange(_sage_const_0 , _sage_const_1000 ):
    for i2 in range(_sage_const_0 , _sage_const_1000 ):
        k1 = i1 + _sage_const_1000  * sum1
        k2 = i2 + _sage_const_1000  * sum2
        tmp = gcd(m1 - k1, m2 - k2)
        if int(tmp).bit_length() == _sage_const_256 :
                print(tmp)
                p = tmp + _sage_const_1 
                q = n // p
                phi = (p - _sage_const_1 ) * (q - _sage_const_1 )
                d = pow(e, -_sage_const_1 , phi)
                m = pow(c, d, n)
                print(long_to_bytes(m))
                exit()
                
