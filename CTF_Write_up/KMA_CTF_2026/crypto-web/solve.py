from itertools import product, islice

import backend.services.account_hash as ah
import backend.services.device_hash as dh
from backend.services.crypto_service import nonce_from_identity


ACC_BASE = [
    0, 10, 14, 8, 8, 2, 3, 5, 9, 1, 9, 14, 1, 13, 4, 10,
    4, 8, 2, 2, 14, 10, 6, 5, 7, 4, 4, 1, 2, 5, 2, 11,
    8, 7, 9, 8, 9, 10, 12, 4, 1, 1, 7, 5, 0, 0, 0, 0,
]

DEV0 = [
    2, 6, 6, 12, 0, 0, 5, 6, 9, 8, 10, 6, 5, 5, 2, 7, 4, 13,
    3, 6, 10, 10, 6, 5, 1, 3, 1, 4, 12, 13, 10, 3, 4, 8, 5, 1,
    6, 8, 7, 6, 0, 13, 10, 0, 0, 0, 3, 0, 9, 4, 10, 6,
]

DEV1 = [
    3, 6, 5, 2, 0, 4, 11, 7, 7, 2, 5, 8, 12, 4, 9, 12, 0, 7,
    7, 5, 9, 10, 1, 9, 9, 11, 11, 4, 13, 1, 10, 12, 13, 13, 3,
    9, 4, 7, 8, 5, 9, 1, 13, 3, 9, 9, 0, 0, 10, 5, 9, 5,
]


def account_from_scrambled_nibbles(nibbles):
    scrambled_bits = []
    for x in nibbles:
        scrambled_bits += [
            (x >> 3) & 1,
            (x >> 2) & 1,
            (x >> 1) & 1,
            x & 1,
        ]

    raw_bits = [0] * ah._MATRIX_INPUT_BITS
    for i, bit in enumerate(scrambled_bits):
        mask_bit = (ah._BIT_MASK >> (ah._MATRIX_INPUT_BITS - 1 - i)) & 1
        raw_bits[ah._BIT_PERMUTATION[i]] = bit ^ mask_bit

    out = 0
    for bit in raw_bits:
        out = (out << 1) | bit
    return out


def invert_device_feistel(value):
    left = value >> dh.FEISTEL_HALF_BITS
    right = value & dh.FEISTEL_HALF_MASK

    for key in reversed(dh.FEISTEL_KEYS):
        old_right = left
        old_left = (right ^ dh._feistel_round(old_right, key)) & dh.FEISTEL_HALF_MASK
        left, right = old_left, old_right

    return (left << dh.FEISTEL_HALF_BITS) | right


def device_from_symbols(symbols):
    value = symbols[0]
    mul = dh.ALPHABET_SIZE

    for pos in range(1, dh.WALK_LENGTH):
        prev = symbols[pos - 1]
        cur = symbols[pos]
        digit = dh.TRANSITION_TABLE[pos - 1][prev].index(cur)
        value += mul * digit
        mul *= dh.BRANCHING_FACTOR

    return invert_device_feistel(value)


def gen_nonce_collision_pairs():
    d0 = device_from_symbols(DEV0)
    d1 = device_from_symbols(DEV1)

    assert dh.device_route_digest(d0) == dh.device_route_digest(d1)

    for suffix in product(range(16), repeat=3):
        n0 = ACC_BASE[:]
        n1 = ACC_BASE[:]

        # relation:
        # n0[0], n0[44] = 0, 0
        # n1[0], n1[44] = 8, 1
        n0[0], n0[44] = 0, 0
        n1[0], n1[44] = 8, 1

        # 3 nibble cuối có thể đổi tùy ý, miễn là giống nhau ở hai bên
        n0[45:48] = suffix
        n1[45:48] = suffix

        a0 = account_from_scrambled_nibbles(n0)
        a1 = account_from_scrambled_nibbles(n1)

        assert ah.account_route_digest(a0) == ah.account_route_digest(a1)
        assert nonce_from_identity(a0, d0) == nonce_from_identity(a1, d1)

        yield a0, d0, a1, d1, nonce_from_identity(a0, d0).hex()


for i, item in enumerate(islice(gen_nonce_collision_pairs(), 10)):
    a0, d0, a1, d1, nonce = item
    print(f"pair {i}")
    print("a0 =", a0)
    print("d0 =", d0)
    print("a1 =", a1)
    print("d1 =", d1)
    print("nonce =", nonce)
    print()

from itertools import product
import random
import backend.services.account_hash as ah

I = (1, 0, 0, 1)

def mat_prod(seq):
    M = I
    for x in seq:
        M = ah._matrix_mul(M, ah._MATRIX_TABLE[x])
    return M

def find_boundary_relation(A):
    seen = {}

    for l, r in product(range(16), repeat=2):
        M = ah._matrix_mul(
            ah._matrix_mul(ah._MATRIX_TABLE[l], A),
            ah._MATRIX_TABLE[r],
        )

        if M in seen:
            l0, r0 = seen[M]
            if (l0, r0) != (l, r):
                return (l0, r0), (l, r)

        seen[M] = (l, r)

    return None

def search_A(max_tries=100000, mid_len=43):
    for t in range(max_tries):
        mid = [random.randrange(16) for _ in range(mid_len)]
        A = mat_prod(mid)

        rel = find_boundary_relation(A)
        if rel:
            return mid, A, rel

    return None

res = search_A()

if res:
    mid, A, rel = res
    print("middle =", mid)
    print("relation =", rel)
else:
    print("not found")