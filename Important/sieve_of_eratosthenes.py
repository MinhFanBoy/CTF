
def sieve_of_eratosthenes(bit):
    lower_limit = 2**bit
    upper_limit = 2**(bit + 1) 
    primes = [True] * (upper_limit - lower_limit)

    for i in range(2, int(upper_limit ** 0.5) + 1):
        if primes[i]:
            for j in range(max(i*i, (lower_limit + i - 1) // i * i), upper_limit, i):
                primes[j - lower_limit] = False

    prime_numbers = [i for i in range(lower_limit, upper_limit) if primes[i - lower_limit]]
    return prime_number
