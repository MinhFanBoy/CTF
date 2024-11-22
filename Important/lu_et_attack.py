
"""

attack on RSA params where:

+ p = 2ga + 1, q = 2gb + 1
+ d = N ^ beta
+ g = N ^ gama

large beta will work ';

"""

from Crypto.Util.number import *
from itertools import *
from tqdm import *

def lu_et_attack(N, e, gamma, beta):
    n = 2
    r = 1
    R = [0,1,2]
    Gamma = [0,beta,1/2]
    miu = gamma
    E = inverse(e,N-1)
    X = int(N^beta)
    Y = int(N^(1/2))

    PR.<x,y> = PolynomialRing(ZZ)
    x,y = PR.gens()
    f1 = E-x
    f2 = N-y


    #attack
    t = 2
    while(1):
        poly=[]
        monomials=set()

        #throw poly
        for j in range(1,n+1):
            if(Gamma[j] / R[j] > miu):
                continue

        for i1 in range(50):
            for i2 in range(50):
                I = [0,i1,i2]
                sum2 = 0
                for i in range(1,len(R)):
                    sum2 += Gamma[i]*I[i]
                if(sum2 > miu*t):
                    continue

                sum1 = 0
                for i in range(1,len(R)):
                    sum1 += R[i]*I[i]
                d = max([0 , ceil(((t-sum1))/r)])
                G = f1^i1*f2^i2*(N-1)^d

                poly.append(G)
                monomials.add(x^i1*y^i2)

        L = Matrix(ZZ,len(poly),len(monomials))

        monomials = sorted(monomials)
        for row,shift in enumerate(poly):
            for col,monomial in enumerate(monomials):
                L[row,col] = shift.monomial_coefficient(monomial)*monomial(X,Y)

        w = L.dimensions()[0]

        #check t
        left = abs(2^((w-1)*w/4) * L.det())
        right = abs(((N-1)^(miu*t) / sqrt(w))^w)


        #if satisfy then LLL
        if(left < right):
            print(L.dimensions())
            res = L.LLL()
            vec1 = res[0]
            vec2 = res[1]

            g1 = 0
            for idx,monomial in enumerate(monomials):
                    g1 += (vec1[idx] // monomial(X,Y)) * monomial
            g1 = g1.change_ring(ZZ)
            g2 = 0
            for idx,monomial in enumerate(monomials):
                    g2 += (vec2[idx] // monomial(X,Y)) * monomial
            g2 = g2.change_ring(ZZ)

            h = g1.sylvester_matrix(g2, y).det()

            res = h.univariate_polynomial().monic().roots()
            d = int(res[0][0])
            return d
        t += 1
