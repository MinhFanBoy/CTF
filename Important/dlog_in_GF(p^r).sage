def hensel_lift(f, p, k, i=0):
    """
    f: đa thức cần tìm nghiệm
    p: số nguyên tố
    k: số mũ của p muốn nâng lên (p^k)
    i: nghiệm thứ i của f mod p
    """
    fp = f.change_ring(Zmod(p))
    g0 = int(fp.roots()[i][0])
    
    result = g0
    power = 1
    
    for i in range(1, k):
        
        curr_poly = (f(result + x * p**power).change_ring(ZZ) / (p**power)).change_ring(Zmod(p))
        ti = int(curr_poly.roots()[0][0])
        result = result + ti * (p**power)
        power += 1
        
    return int(result)



def d_log(k, base, p, r): 

    # solve k = base ^ x (mod p^r)
    
    def d_log_sub(k, base, p, r):

    # sol that: base ^ x = k (mod p ^ r) => find x

        q = p - 1
        c = (ZZ(pow(k, q, p ^ r)) - 1) // (p ^ (r - 1))
        d = (ZZ(pow(base, q, p ^ r)) - 1) // (p ^ (r - 1))
        x = ZZ((pow(d, -1, p) * c) % p)

        return x
    
    k = ZZ(k)
    base = ZZ(base)
    xs = []

    for i in range(r-1):
        xi = d_log_sub(k, base, p, i + 2)
        xs.append(xi)
        k = ZZ(k * pow(base,-xi,p^r) % p^r)
        base = ZZ(pow(base,p,p^r))
    return ZZ(xs, p)

def d_log(k, base, p, r): 

    # solve k = base ^ x (mod p ^ r)
    R = Zp(p, prec = r)
    return (R(k).log() / R(base).log()).lift()
