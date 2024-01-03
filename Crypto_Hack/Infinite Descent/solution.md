# Crypto hack

---

**_Descrption:_** Infinite Descent

Finding large primes is slow, so I've devised an optimisation.

Challenge files:
  - [descent.py](https://cryptohack.org/static/challenges/descent_240fda375202c97a3cbaf3fdedbb8266.py)
  - [output.txt](https://cryptohack.org/static/challenges/output_14f82a67efe7b7edffb810dbb7ab5f27.txt)

---

Khi xem file descent.py thì thấy q và p có tính chất sau:
  + q = r + a, p = r + b
  + r > a >= 4b

    => 2r > p > q
những tính chất này thỏa mãn yêu cầu cơ bản của fermat attack.

Ý tưởng:
với N là tích của 2 số nt có thể viết dc dưới dạng N = (a - b)(a + b)
=> N = a^2 - b^2 => b^2 = a^2 - N
khi hai số nguyên tố gần nhau thì ta có thể dễ dàng thấy a = sqrt(n) mà hai số nguyên tố gần nhau thì b cx nhỏ từ đó có thể dễ dàng brute froce a để tìm ra b = sqrt(a ** 2 - n)

