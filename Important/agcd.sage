"""

find agcd

+ N: list of int
+ R: 

"""
def agcd(N: list[int], R):
  n = N[0]
  
  M = block_matrix([
      [matrix([[R]]), column_matrix(N[1:]).T],
      [0, diagonal_matrix([-n]* (len(N) - 1)) ]
  ])
  
  q = int(abs(M.LLL()[0][0] // R)))
  p = n // q
  return p
