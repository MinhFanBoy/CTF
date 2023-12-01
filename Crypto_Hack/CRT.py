def CRT( M_i:list, a_i:list ) -> int:
    m = 1
    for x in M_i:
        m*= x
    total = 0
    for x in range(len(M_i)):
        m_i = m//M_i[x]
        total += a_i[x]*(m_i)*pow( m_i,-1, M_i[x] )
    return total

M = [5,11,17]
a = [2,3,5]
print(CRT(M,a))

print(6482 % 935)