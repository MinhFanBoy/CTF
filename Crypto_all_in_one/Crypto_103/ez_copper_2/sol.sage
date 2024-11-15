from Crypto.Util.number import *
from tqdm import *

def small_roots(f, X, beta=1.0, m=None):
    N = f.parent().characteristic()
    delta = f.degree()
    if m is None:
        epsilon = RR(beta^2/f.degree() - log(2*X, N))
        m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
    t = int((delta*m*(1/beta - 1)).floor())
    print(f"m = {m}")
    
    f = f.monic().change_ring(ZZ)
    P,(x,) = f.parent().objgens()
    g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta)]
    g.extend([x**i * f**m for i in range(t)]) 
    B = Matrix(ZZ, len(g), delta*m + max(delta,t))

    for i in range(B.nrows()):
        for j in range(g[i].degree()+1):
            B[i,j] = g[i][j]*X**j

    B =  B.LLL()
    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <= X])
    return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]
num = 215656441
last = 2*3*5
bits = 282

n = 83732821313465518052403665361614770500711747426707910445616394700719876467737514967114877768176244233541342950517438107504392659632618504678367884223695674258126620001220856677629607205209582904215330731871567514530350222492246762740556482040907225061791231222448377878854527601783227627969726021295513927063
c = 46663818733755991848242947341712498383456884024793897130170411388799402223110989123025227270450872334684154450132747808192836148157068113180136519163245994436646022864578219391320904777242102617963109623497099134092899460260651347833764105572783843769863133591669278971958095602865992957181139586462882547338
leak1 = 1166802227519044965330497437183661580954600955790078699599066071608461
leak2 = 100652187

ph = (leak1 << bits) - ((leak1 << bits) % (last*num))
possible_i = []
for i in range(last):
    temp = i*num + leak2
    if(GCD(temp,last) == 1):
        possible_i.append(temp)

PR.<x> = PolynomialRing(Zmod(n))
# 5/8
for i in tqdm(possible_i):
    f = ph + (last*num)*x + i
    f = f.monic()
    
    res = small_roots(f, X = (2^bits // (last*num)) , beta=0.499,m=25)
    if(res != []):
        p = int(ph + (last*num)*int(res[0]) +i)
        q = n // p
        m = pow(c,(inverse(65537,(p-1)*(q-1))),n)
        print(long_to_bytes(int(m)))
        break
    # NSSCTF{An0t3hr_b3tt3r_m3th0d_t0_brut3f0rc3_c0pp3r!}