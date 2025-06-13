# run with `sage -python attack.sage`
from pwn import *
from sage.all import *
import itertools
import ast
import hashlib
from Crypto.Cipher import AES
import sys
assert(sys.version_info.major >= 3)

e2 = 0xD8
e3 = 0x89
p = (2**e2)*(3**e3)-1
x = var('x')
K = GF(p**2, 'ii', modulus=x**2+1)
ii = K.gen()

E0 = EllipticCurve(K, [0,6,0,1,0])
xP20 = 0x00003CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48
xP21 = 0x0001AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50
yP20 = 0x0001AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0
yP21 = 0x0000FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F
xQ20 = 0x0000C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C
xQ21 = 0x000025DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5
yQ20 = 0x0001D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5
yQ21 = 0x0000E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6
xP30 = 0x00008664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9
xP31 = 0x00000000
yP30 = 0x00006AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B
yP31 = 0x00000000
xQ30 = 0x00012E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846
xQ31 = 0x00000000
yQ30 = 0x00000000
yQ31 = 0x0000EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2
P2 = E0(xP20+ii*xP21, yP20+ii*yP21)
Q2 = E0(xQ20+ii*xQ21, yQ20+ii*yQ21)
P3 = E0(xP30+ii*xP31, yP30+ii*yP31)
Q3 = E0(xQ30+ii*xQ31, yQ30+ii*yQ31)

def elem_to_coefficients(x):
    l = x.polynomial().list()
    l += [0]*(2-len(l))
    return l

def elem_to_bytes(x):
    n = ceil(log(p,2)/8)
    x0,x1 = elem_to_coefficients(x) # x == x0 + ii*x1
    x0 = ZZ(x0).digits(256, padto=n)
    x1 = ZZ(x1).digits(256, padto=n)
    return bytes(x0+x1)

def isogen3(sk3):
    Ei = E0
    P = P2
    Q = Q2
    S = P3+sk3*Q3
    for i in range(e3):
        phi = Ei.isogeny((3**(e3-i-1))*S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei,P,Q)

def isoex3(sk3, pk2):
    Ei, P, Q = pk2
    S = P+sk3*Q
    for i in range(e3):
        R = (3**(e3-i-1))*S
        phi = Ei.isogeny(R)
        Ei = phi.codomain()
        S = phi(S)
    return Ei

def isogen2(sk2):
    Ei = E0
    P = P3
    Q = Q3
    S = P2+sk2*Q2
    for i in range(e2):
        phi = Ei.isogeny((2**(e2-i-1))*S)
        Ei = phi.codomain()
        S = phi(S)
        P = phi(P)
        Q = phi(Q)
    return (Ei,P,Q)

def isoex2(sk2, pk3):
    Ei, P, Q = pk3
    S = P+sk2*Q
    for i in range(e2):
        R = (2**(e2-i-1))*S
        phi = Ei.isogeny(R)
        Ei = phi.codomain()
        S = phi(S)
    return Ei

def oracle(EA, phiAPB, phiAQB, EAB):
    send_public_key(EA, phiAPB, phiAQB)
    shared = EAB.j_invariant()

    key = hashlib.sha256(elem_to_bytes(shared)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    pt = b"Hello world.\x00\x00\x00\x00"
    ct = cipher.encrypt(pt).hex()
    r.clean()
    r.sendline(ct)
    ans = r.recvline().strip()
    print('ORACLE:', ans)
    if  b"Good ciphertext." in ans:
        return True
    elif b"Bad ciphertext!" in ans:
        return False
    else:
        assert False, "Oracle response unknown"

## GPST attack, assumes sk has shape (1, alpha)
def attack(eA, eB, E0, PA, QA, PB, QB, EB, phiBPA, phiBQA):
    # PA,QA,PB,QB are not used besides key generation
    print("staring attack...")
    load("./sqrts.sage") # load square roots because sage fails to compute them
    K = Integer(0)

    print('KeyGen...')
    skA = randint(1,2**eA-1)
    EA, phiAPB, phiAQB = isogen2(skA)
    # tests done by the server:
    assert(phiAPB*(3**eB) == EA(0) and phiAPB*(3**(eB-1)) != EA(0))
    assert(phiAQB*(3**eB) == EA(0) and phiAQB*(3**(eB-1)) != EA(0))
    assert(phiAPB.weil_pairing(phiAQB, Integer(3**eB)) == (PB.weil_pairing(QB, Integer(3**eB)))**Integer(2**eA))
    EAB = isoex2(skA, (EB,phiBPA,phiBQA)) # (sk2,pk3)
    print('...done')

    for i in range(eB - 3):
        print('\n===  i =', i,' / ', eB-3, '  ===')
        alpha = 0
        theta = sqrts[i]

        # computing next bit (like if attacking Alice)
        #R_ = theta * (phiAPB - (2**(eA - i - 1) * K) * phiAQB)
        #S_ = theta * (1 + 2**(eA - i - 1)) * phiAQB
        #o = oracle(EA, R_, S_, EAB)
        #if not o:
        #    K += alpha*2**i
        #print("--- current :", bin(K))

        for x in range(2): # computing a trit (Bob's key), cycle to l-1
            R_ = theta * (phiAPB - (3**(eB - i - 1) * (K+(x*3**i))) * phiAQB)
            S_ = theta * (1 + 3**(eB - i - 1)) * phiAQB
            o = oracle(EA, R_, S_, EAB)
            if o:
                K += x*3**i
                break
        if not o:
            K += 2*(3**i) # if trit is not {0,1} then it's 2

        print("---------current----------:\n",\
              K.str(base=3),\
              "\n---------------------------")

    ## bruteforcing the rest of the key
    print("bruteforcing last trits...")
    for i in range(3):
        for j in range(3):
            for k in range(3):
               print("===  i,j,k: ", (i,j,k), "  ===")
               K_ = K
               K_ += i*3**(eB-1) + j*3**(eB-2) + k*3**(eB-3)
               EB_, _, _ = isogen3(K_)
               if EB_.j_invariant() == EB.j_invariant():
                   solution = K_ % 3**eB
                   return solution

    print("FAILED:", K)
    return "Key not found"

def read_public_key():
    print("reading public key...")
    r.readuntil('a1: ')
    a1 = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('a1=',a1)
    r.readuntil('a2: ')
    a2 = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('a2=',a2)
    r.readuntil('a3: ')
    a3 = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('a3=',a3)
    r.readuntil('a4: ')
    a4 = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('a4=',a4)
    r.readuntil('a6: ')
    a6 = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('a6=',a6)
    r.readuntil('Px: ')
    Px = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('Px=',Px)
    r.readuntil('Py: ')
    Py = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('Py=',Py)
    r.readuntil('Qx: ')
    Qx = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('Qx=',Qx)
    r.readuntil('Qy: ')
    Qy = ast.literal_eval(r.readline().strip().decode('ascii'))
    print('Qy=',Qy)

    E = EllipticCurve(K, list(map(K,[a1,a2,a3,a4,a6])))
    phiP = E((Px,Py))
    phiQ = E((Qx,Qy))
    return E, phiP, phiQ

def send_public_key(E, phiP, phiQ):
    print("sending public key...")
    for tup in map(elem_to_coefficients, [E.a1(),E.a2(),E.a3(),E.a4(),E.a6()]):
        r.readuntil('re: ')
        r.sendline(str(tup[0]))
        r.readuntil('im: ')
        r.sendline(str(tup[1]))
    r.readuntil('re: ') #Px
    r.sendline(str(elem_to_coefficients(phiP[0])[0]))
    r.readuntil('im: ')
    r.sendline(str(elem_to_coefficients(phiP[0])[1]))
    r.readuntil('re: ') #Py
    r.sendline(str(elem_to_coefficients(phiP[1])[0]))
    r.readuntil('im: ')
    r.sendline(str(elem_to_coefficients(phiP[1])[1]))
    r.readuntil('re: ') #Qx
    r.sendline(str(elem_to_coefficients(phiQ[0])[0]))
    r.readuntil('im: ')
    r.sendline(str(elem_to_coefficients(phiQ[0])[1]))
    r.readuntil('re: ') #Qy
    r.sendline(str(elem_to_coefficients(phiQ[1])[0]))
    r.readuntil('im: ')
    r.sendline(str(elem_to_coefficients(phiQ[1])[1]))

if __name__ == "__main__":
    local = True
    if local:
        r = process(['sage', './server.sage'])
        goal = Integer(r.readline().decode('ascii').strip().split(' ')[-1])
        print("GOAL:", goal.str(base=3))
    else:
        IP = '149.28.9.162'
        PORT = 31337
        r = remote(IP, PORT)
        # proof of work:
        prefix, size = r.readline().split(b'with ')[1].split(b' of length ')
        size = int(size.split(b' so its')[0])
        print("POW: prefix", prefix, "\tsize", size)
        for tup in itertools.product(string.ascii_letters + string.digits, repeat=8):
            l = prefix.decode('ascii') + ''.join(tup)
            if hashlib.sha256(l.encode('ascii')).hexdigest()[-7:] == "fffffff":
                print("got proof of work!", l)
                break
        r.sendline(l)

    # recover Bob's secret key
    EB,phiBPA,phiBQA = read_public_key()
    alpha_ = attack(e2, e3, E0, P2, Q2, P3, Q3, EB, phiBPA, phiBQA) # (1,alpha_)
    assert alpha_ != "Key not found", "Failed to compute secret key"
    print("===== found secretkey:", alpha_, "=====")

    # final step, send super_secret_hash encrypted:
    super_secret_hash = hashlib.sha256(str(alpha_).encode('ascii')).digest()[:16]
    skA = randint(1,2**e2-1)
    EA, phiAPB, phiAQB = isogen2(skA)
    EAB = isoex2(skA,(EB,phiBPA,phiBQA)) # (sk2,pk3)
    shared = EAB.j_invariant()

    send_public_key(EA, phiAPB, phiAQB)

    print('shared secret:', shared)
    key = hashlib.sha256(elem_to_bytes(shared)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(super_secret_hash).hex()
    print(r.clean())
    r.sendline(ct)
    r.interactive()
