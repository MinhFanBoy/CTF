from __future__ import annotations

import argparse

import backend.services.account_hash as account_hash
import backend.services.device_hash as device_hash
from backend.services.crypto_service import nonce_from_identity


# Scrambled 48-nibble account path for the known account collision family.
# For positions 0 and 44, this source path uses (0, 0), while the colliding
# path uses (8, 1). Positions 45..47 can be chosen freely.
ACCOUNT_BASE_NIBBLES = [
    0, 10, 14, 8, 8, 2, 3, 5, 9, 1, 9, 14,
    1, 13, 4, 10, 4, 8, 2, 2, 14, 10, 6, 5,
    7, 4, 4, 1, 2, 5, 2, 11, 8, 7, 9, 8,
    9, 10, 12, 4, 1, 1, 7, 5, 0, 0, 0, 0,
]


DEVICE_PATH_0 = [
    2, 6, 6, 12, 0, 0, 5, 6, 9, 8, 10, 6, 5, 5, 2, 7, 4, 13,
    3, 6, 10, 10, 6, 5, 1, 3, 1, 4, 12, 13, 10, 3, 4, 8, 5,
    1, 6, 8, 7, 6, 0, 13, 10, 0, 0, 0, 3, 0, 9, 4, 10, 6,
]

DEVICE_PATH_1 = [
    3, 6, 5, 2, 0, 4, 11, 7, 7, 2, 5, 8, 12, 4, 9, 12, 0, 7,
    7, 5, 9, 10, 1, 9, 9, 11, 11, 4, 13, 1, 10, 12, 13, 13,
    3, 9, 4, 7, 8, 5, 9, 1, 13, 3, 9, 9, 0, 0, 10, 5, 9, 5,
]


def nibbles_to_bits(nibbles: list[int]) -> list[int]:
    bits: list[int] = []
    for nibble in nibbles:
        bits.extend(
            [
                (nibble >> 3) & 1,
                (nibble >> 2) & 1,
                (nibble >> 1) & 1,
                nibble & 1,
            ]
        )
    return bits


def account_from_scrambled_nibbles(nibbles: list[int]) -> int:
    scrambled = nibbles_to_bits(nibbles)
    plain_bits = [0] * 192

    for i, bit in enumerate(scrambled):
        mask_bit = (account_hash._BIT_MASK >> (191 - i)) & 1
        plain_bits[account_hash._BIT_PERMUTATION[i]] = bit ^ mask_bit

    value = 0
    for bit in plain_bits:
        value = (value << 1) | bit
    return value


def account_collision_pair(index: int) -> tuple[int, int]:
    if not (0 <= index < 16**3):
        raise ValueError("index must be in range 0..4095")

    suffix = [(index >> 8) & 0xF, (index >> 4) & 0xF, index & 0xF]

    left = ACCOUNT_BASE_NIBBLES[:]
    right = ACCOUNT_BASE_NIBBLES[:]

    left[0], left[44] = 0, 0
    right[0], right[44] = 8, 1

    left[45:48] = suffix
    right[45:48] = suffix

    return account_from_scrambled_nibbles(left), account_from_scrambled_nibbles(right)


def inverse_input_permutation(value: int) -> int:
    left = value >> device_hash.FEISTEL_HALF_BITS
    right = value & device_hash.FEISTEL_HALF_MASK

    for key in reversed(device_hash.FEISTEL_KEYS):
        old_left = (right ^ device_hash._feistel_round(left, key)) & device_hash.FEISTEL_HALF_MASK
        old_right = left
        left, right = old_left, old_right

    return (left << device_hash.FEISTEL_HALF_BITS) | right


def device_from_symbol_path(symbols: list[int]) -> int:
    if len(symbols) != device_hash.WALK_LENGTH:
        raise ValueError("bad symbol path length")

    value = symbols[0]
    multiplier = device_hash.ALPHABET_SIZE

    for position in range(1, device_hash.WALK_LENGTH):
        previous = symbols[position - 1]
        current = symbols[position]
        digit = device_hash.TRANSITION_TABLE[position - 1][previous].index(current)
        value += multiplier * digit
        multiplier *= device_hash.BRANCHING_FACTOR

    return inverse_input_permutation(value)


def device_collision_pair() -> tuple[int, int]:
    return device_from_symbol_path(DEVICE_PATH_0), device_from_symbol_path(DEVICE_PATH_1)


def verify_pair(a0: int, a1: int, d0: int, d1: int) -> None:
    assert account_hash.account_route_digest(a0) == account_hash.account_route_digest(a1)
    assert device_hash.device_route_digest(d0) == device_hash.device_route_digest(d1)
    assert nonce_from_identity(a0, d0) == nonce_from_identity(a1, d1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--count", type=int, default=8)
    parser.add_argument("--start", type=int, default=0)
    args = parser.parse_args()

    d0, d1 = device_collision_pair()
    print(f"d0 = {d0}")
    print(f"d1 = {d1}")
    print(f"device_digest = {device_hash.device_route_digest(d0).hex()}")
    print()

    for index in range(args.start, args.start + args.count):
        a0, a1 = account_collision_pair(index % (16**3))
        verify_pair(a0, a1, d0, d1)
        nonce = nonce_from_identity(a0, d0).hex()
        print(f"[{index}]")
        print(f"a0 = {a0}")
        print(f"a1 = {a1}")
        print(f"nonce = {nonce}")
        print()


if __name__ == "__main__":
    main()
