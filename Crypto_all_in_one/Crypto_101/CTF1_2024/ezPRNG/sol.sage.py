

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1000 = Integer(1000); _sage_const_0 = Integer(0); _sage_const_2 = Integer(2); _sage_const_1 = Integer(1)
for _ in range(_sage_const_1000 ):
    i = _
    nextbit=_sage_const_0 
    while i!=_sage_const_0 :
        nextbit**=(i%_sage_const_2 )
        i=i//_sage_const_2 
        
    if nextbit != _sage_const_1 :
        print(_, bin(_))
        

