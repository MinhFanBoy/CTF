

# This file was *autogenerated* from the file sol.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1p0 = RealNumber('1.0'); _sage_const_2 = Integer(2); _sage_const_7 = Integer(7); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_20304817598463991883487911425007927214135740826150882692657608404060781116387976327509281041677948119173928648751205240686682904704601086882134602075008186227364732648337539221512524800875230120183740426722086488143679856177002068856911689386346260227545638754513723197073169314634515297819111746527980650406024533140966706487847121511407833611739619493873042466218612052791074001203074880497201822723381092411392045694262494838335876154820241827541930328508349759776586915947972105562652406402019214248895741297737940426853122270339018032192731304168659857343755119716209856895953244774989436447915329774815874911183 = Integer(20304817598463991883487911425007927214135740826150882692657608404060781116387976327509281041677948119173928648751205240686682904704601086882134602075008186227364732648337539221512524800875230120183740426722086488143679856177002068856911689386346260227545638754513723197073169314634515297819111746527980650406024533140966706487847121511407833611739619493873042466218612052791074001203074880497201822723381092411392045694262494838335876154820241827541930328508349759776586915947972105562652406402019214248895741297737940426853122270339018032192731304168659857343755119716209856895953244774989436447915329774815874911183); _sage_const_65537 = Integer(65537); _sage_const_7556587235137470264699910626838724733676624636871243497222431220151475350453511634500082904961419456561498962154902587302652809217390286599510524553544201322937261018961984214725167130840149912862814078259778952625651511254849935498769610746555495241583284505893054142602024818465021302307166854509140774804110453227813731851908572434719069923423995744812007854861031927076844340649660295411912697822452943265295532645300241560020169927024244415625968273457674736848596595931178772842744480816567695738191767924194206059251669256578685972003083109038051149451286043920980235629781296629849866837148736553469654985208 = Integer(7556587235137470264699910626838724733676624636871243497222431220151475350453511634500082904961419456561498962154902587302652809217390286599510524553544201322937261018961984214725167130840149912862814078259778952625651511254849935498769610746555495241583284505893054142602024818465021302307166854509140774804110453227813731851908572434719069923423995744812007854861031927076844340649660295411912697822452943265295532645300241560020169927024244415625968273457674736848596595931178772842744480816567695738191767924194206059251669256578685972003083109038051149451286043920980235629781296629849866837148736553469654985208); _sage_const_1511538174156308717222440773296069138085147882345360632192251847987135518872444058511319064 = Integer(1511538174156308717222440773296069138085147882345360632192251847987135518872444058511319064); _sage_const_352 = Integer(352); _sage_const_1024 = Integer(1024); _sage_const_350 = Integer(350)
from Crypto.Util.number import *
from random import *
from gmpy2 import *


def small_roots(f, X, beta=_sage_const_1p0 , m=None):
    N = f.parent().characteristic()
    delta = f.degree()
    if m is None:
        epsilon = RR(beta**_sage_const_2 /f.degree() - log(_sage_const_2 *X, N))
        m = max(beta**_sage_const_2 /(delta * epsilon), _sage_const_7 *beta/delta).ceil()
    t = int((delta*m*(_sage_const_1 /beta - _sage_const_1 )).floor())

    f = f.monic().change_ring(ZZ)
    P,(x,) = f.parent().objgens()
    g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta)]
    g.extend([x**i * f**m for i in range(t)]) 
    B = Matrix(ZZ, len(g), delta*m + max(delta,t))

    for i in range(B.nrows()):
        for j in range(g[i].degree()+_sage_const_1 ):
            B[i,j] = g[i][j]*X**j

    B =  B.LLL()
    f = sum([ZZ(B[_sage_const_0 ,i]//X**i)*x**i for i in range(B.ncols())])
    roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <= X])
    return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]
import itertools

def small_roots(f, bounds, m=_sage_const_1 , d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), _sage_const_1 )
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(_sage_const_0 )
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+_sage_const_1 ):
		base = N**(m-i) * f**i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, _sage_const_1 /factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -_sage_const_1 :
			H.pop()
		elif I.dimension() == _sage_const_0 :
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []
n = _sage_const_20304817598463991883487911425007927214135740826150882692657608404060781116387976327509281041677948119173928648751205240686682904704601086882134602075008186227364732648337539221512524800875230120183740426722086488143679856177002068856911689386346260227545638754513723197073169314634515297819111746527980650406024533140966706487847121511407833611739619493873042466218612052791074001203074880497201822723381092411392045694262494838335876154820241827541930328508349759776586915947972105562652406402019214248895741297737940426853122270339018032192731304168659857343755119716209856895953244774989436447915329774815874911183 
e = _sage_const_65537 
c = _sage_const_7556587235137470264699910626838724733676624636871243497222431220151475350453511634500082904961419456561498962154902587302652809217390286599510524553544201322937261018961984214725167130840149912862814078259778952625651511254849935498769610746555495241583284505893054142602024818465021302307166854509140774804110453227813731851908572434719069923423995744812007854861031927076844340649660295411912697822452943265295532645300241560020169927024244415625968273457674736848596595931178772842744480816567695738191767924194206059251669256578685972003083109038051149451286043920980235629781296629849866837148736553469654985208 
leak = _sage_const_1511538174156308717222440773296069138085147882345360632192251847987135518872444058511319064 

h = bin(iroot(n, _sage_const_2 )[_sage_const_0 ])[_sage_const_2 :_sage_const_352 ]

"""

leak = (pow(p,q,n) + pow(q,p,n))
p = q + x
l = p ^ q + q ^ p
# l = (q + x) ^ q + q ^ (q + x) = (q ** 2 + qx) ^ q + q ^ x

l * (p ^ p) = p ^ (q * p) + (q * p) ^ p mod n
l * (p ^ p) = p ^ (n) + (n) ^ p mod n
# l * (p ^ p) = p + k *p * q

# l = p ^ q + q ^ p + k * q * p
# l = p mod q

phi = n - q - p + 1
phi + p - 1 = n - q
l = p ^ (phi + p - 1) mod n
l = p ^ (p - 1) mod n

l = p + q

n = (h + _q) * (h + _p)
a + b = p
a - b = q

2 * a = p + q = 2 * h + x * (2 ** 300) + l = 2 ** 1025
2 * b = p - q = y = 2 ** (1024 - 350)
"""
a = _sage_const_1  << _sage_const_1024 
b = _sage_const_1  << (_sage_const_1024  - _sage_const_350 ) - _sage_const_1 

print(((a - b) * (a + b)).bit_length())
