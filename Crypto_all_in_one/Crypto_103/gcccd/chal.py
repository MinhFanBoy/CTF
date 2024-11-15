
from Crypto.Util.number import getStrongPrime, GCD, bytes_to_long
import os
from flag import flag

def long_to_bytes(long_int, block_size=None):
    """Convert a long integer to bytes, optionally right-justified to a given block size."""
    bytes_data = long_int.to_bytes((long_int.bit_length() + 7) // 8, 'big')
    return bytes_data if not block_size else bytes_data.rjust(block_size, b'\x00')

def gen_keys(bits=512, e=5331):
    """Generate RSA modulus n and public exponent e such that GCD((p-1)*(q-1), e) == 1."""
    while True:
        p, q = getStrongPrime(bits), getStrongPrime(bits)
        n = p * q
        if GCD((p-1) * (q-1), e) == 1:
            return n, e

def pad(m, n):
    """Pad the message m for RSA encryption under modulus n using PKCS#1 type 1."""
    mb, nb = long_to_bytes(m), long_to_bytes(n)
    assert len(mb) <= len(nb) - 11
    padding = os.urandom(len(nb) - len(mb) - 3).replace(b'\x01', b'')
    return bytes_to_long(b'\x00\x01' + padding + b'\x00' + mb)

def encrypt(m, e, n):
    """Encrypt message m with RSA public key (e, n)."""
    return pow(m, e, n)

n, e = gen_keys()
m = pad(bytes_to_long(flag), n)
c1, c2 = encrypt(m, e, n), encrypt(m // 2, e, n)

print(f"n = {n}\ne = {e}\nc1 = {c1}\nc2 = {c2}")

# n = 128134155200900363557361770121648236747559663738591418041443861545561451885335858854359771414605640612993903005548718875328893717909535447866152704351924465716196738696788273375424835753379386427253243854791810104120869379525507986270383750499650286106684249027984675067236382543612917882024145261815608895379
# e = 5331
# c1 = 60668946079423190709851484247433853783238381043211713258950336572392573192737047470465310272448083514859509629066647300714425946282732774440406261265802652068183263460022257056016974572472905555413226634497579807277440653563498768557112618320828785438180460624890479311538368514262550081582173264168580537990
# c2 = 43064371535146610786202813736674368618250034274768737857627872777051745883780468417199551751374395264039179171708712686651485125338422911633961121202567788447108712022481564453759980969777219700870458940189456782517037780321026907310930696608923940135664565796997158295530735831680955376342697203313901005151
