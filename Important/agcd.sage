"""

find agcd

+ N: list of int
+ R_bits: 

"""
def agcd(N: list[int], R_bits):
  n = N[0]
  
  M = block_matrix([
      [matrix([[2 ** (R_bits)]]), column_matrix(N[1:]).T],
      [0, diagonal_matrix([-n]* (len(N) - 1)) ]
  ])
  
  q = int(abs(M.LLL()[0][0] // (2 ** (R_bits))))
  p = n // q
  return p
