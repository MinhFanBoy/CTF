import itertools

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), 1)
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
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
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []

from Crypto.Util.number import long_to_bytes

n=120838778421252867808799302603972821425274682456261749029016472234934876266617266346399909705742862458970575637664059189613618956880430078774892479256301209695323302787221508556481196281420676074116272495278097275927604857336484564777404497914572606299810384987412594844071935546690819906920254004045391585427
c=118961547254465282603128910126369011072248057317653811110746611348016137361383017921465395766977129601435508590006599755740818071303929227578504412967513468921191689357367045286190040251695094706564443721393216185563727951256414649625597950957960429709583109707961019498084511008637686004730015209939219983527
m0=13292147408567087351580732082961640130543313742210409432471625281702327748963274496942276607

m0 = m0 << 208

F.<m_> = PolynomialRing(Zmod(n))

f = (m0 + m_) ** 3 - c

m_ = int(small_roots(f, [2 ** 208], m = 5, d = 3)[0][0])

print(long_to_bytes(m0 + m_))