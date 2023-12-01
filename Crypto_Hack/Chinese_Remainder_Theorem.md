# Crypto Hack

src = [Crypto_Hack](https://cryptohack.org/courses/modular/crt1/)

---

**_description:_**

Given the following set of linear congruences:

x ≡ 2 mod 5
x ≡ 3 mod 11
x ≡ 5 mod 17


Find the integer a such that x ≡ a mod 935

---

Để làm dc bài này thì chỉ cần code theo công thức là xong.

Code:

    def CRT( M_i:list, a_i:list ) -> int:
      m,total = 1,0
      for x in M_i:
          m*= x
  
      for x in range(len(M_i)):
          m_i = m//M_i[x]
          total += a_i[x]*(m_i)*pow( m_i,-1, M_i[x] )
      return total

> 872
