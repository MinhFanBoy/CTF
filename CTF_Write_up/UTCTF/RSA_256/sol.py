from factordb.factordb import FactorDB

N = 77483692467084448965814418730866278616923517800664484047176015901835675610073
e = 65537
c = 43711206624343807006656378470987868686365943634542525258065694164173101323321
s = FactorDB(N)
s.connect()
n = s.get_factor_list()
phi = (n[0]-1)*(n[1]-1)
d = pow(e, -1, phi)
m = pow(c, d, N)
print(bytes.fromhex(hex(m)[2:]).decode())

