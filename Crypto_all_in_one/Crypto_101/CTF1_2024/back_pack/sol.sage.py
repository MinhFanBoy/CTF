

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_871114172567853490297478570113449366988793760172844644007566824913350088148162949968812541218339 = Integer(871114172567853490297478570113449366988793760172844644007566824913350088148162949968812541218339); _sage_const_3245882327 = Integer(3245882327); _sage_const_3130355629 = Integer(3130355629); _sage_const_2432460301 = Integer(2432460301); _sage_const_3249504299 = Integer(3249504299); _sage_const_3762436129 = Integer(3762436129); _sage_const_3056281051 = Integer(3056281051); _sage_const_3484499099 = Integer(3484499099); _sage_const_2830291609 = Integer(2830291609); _sage_const_3349739489 = Integer(3349739489); _sage_const_2847095593 = Integer(2847095593); _sage_const_3532332619 = Integer(3532332619); _sage_const_2406839203 = Integer(2406839203); _sage_const_4056647633 = Integer(4056647633); _sage_const_3204059951 = Integer(3204059951); _sage_const_3795219419 = Integer(3795219419); _sage_const_3240880339 = Integer(3240880339); _sage_const_2668368499 = Integer(2668368499); _sage_const_4227862747 = Integer(4227862747); _sage_const_2939444527 = Integer(2939444527); _sage_const_3375243559 = Integer(3375243559); _sage_const_45893025064 = Integer(45893025064); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_2 = Integer(2)
from Crypto.Util.number import *

enc=_sage_const_871114172567853490297478570113449366988793760172844644007566824913350088148162949968812541218339 
a=[_sage_const_3245882327 , _sage_const_3130355629 , _sage_const_2432460301 , _sage_const_3249504299 , _sage_const_3762436129 , _sage_const_3056281051 , _sage_const_3484499099 , _sage_const_2830291609 , _sage_const_3349739489 , _sage_const_2847095593 , _sage_const_3532332619 , _sage_const_2406839203 , _sage_const_4056647633 , _sage_const_3204059951 , _sage_const_3795219419 , _sage_const_3240880339 , _sage_const_2668368499 , _sage_const_4227862747 , _sage_const_2939444527 , _sage_const_3375243559 ]
bag=_sage_const_45893025064 

a = column_matrix(a)

M = block_matrix(ZZ,[
    [_sage_const_1 , a],
    [_sage_const_0 , matrix([[-bag]])]
])

M = M.LLL()

for i in M:
    if i[-_sage_const_1 ] == _sage_const_0  and all([j in [_sage_const_0 ,_sage_const_1 ] for j in i[:-_sage_const_1 ]]):
        i = "".join([str(j) for j in i[:-_sage_const_1 ]])
        p = int(i, _sage_const_2 )
        print(long_to_bytes(enc ^ p))
