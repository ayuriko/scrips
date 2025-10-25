#!/usr/bin/env python3
"""Find and display all prime numbers up to 100."""

from typing import List


def sieve_of_eratosthenes(limit: int) -> List[int]:
    """Return a list of prime numbers up to ``limit`` using the sieve algorithm."""
    if limit < 2:
        return []

    is_prime = [True] * (limit + 1)
    is_prime[0] = is_prime[1] = False

    for base in range(2, int(limit ** 0.5) + 1):
        if is_prime[base]:
            # Strike out all multiples of the current base prime number.
            for multiple in range(base * base, limit + 1, base):
                is_prime[multiple] = False

    return [number for number, prime in enumerate(is_prime) if prime]


def main() -> None:
    """Compute and print the prime numbers up to 100."""
    limit = 100
    primes = sieve_of_eratosthenes(limit)
    print(f"Prime numbers up to {limit}:")
    print(" ".join(str(prime) for prime in primes))


if __name__ == "__main__":
    main()
