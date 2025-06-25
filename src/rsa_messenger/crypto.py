"""
crypto.py - Cryptographic and number-theoretic functions for RSA Messenger
"""
from math import cbrt, ceil, exp, floor, isqrt, log, log2, sqrt
from secrets import randbelow
from typing import Union, overload, Literal
from .utils import advanced_format_seconds

from sympy import prevprime, nextprime, randprime  # type: ignore
# NOTE: Use gmpy for more efficient primality testing?

def prev_prime(n: int, ith: int = 0) -> int:
    """Find the previous prime number less than or equal to n after skipping ith primes. Wraps sympy's prevprime."""
    return prevprime(n, ith) # type: ignore

def next_prime(n: int, ith: int) -> int:
    """Find the next prime number greater than or equal to n after skipping ith primes. Wraps sympy's nextprime."""
    return nextprime(n, ith) # type: ignore

def is_prime(n: int) -> bool:
    """Check if n is a prime number using the Baillie-PSW primality test."""
    if n < 2:
        return False
    return baillie_psw_test(n)

def rand_prime(a: int, b: int) -> int | None:
    """Generate a random prime number in the range [a, b]. Wraps sympy's randprime."""
    return randprime(a, b) # type: ignore

def randint(a: int, b: int) -> int:
    """Random integer in range [a, b]"""
    return a + randbelow(b - a + 1)

def binary_pow_left_right(base: int | float, exponent: int) -> int | float:
    """Binary exponentiation (left-to-right)"""
    if exponent == 0:
        return 1
    result = base
    for m in f"{abs(exponent):b}"[1:]:
        result = result**2 * (base if m == "1" else 1)
    return result if exponent >= 0 else 1 / result

def binary_pow_right_left(base: int | float, exponent: int) -> int | float:
    """Binary exponentiation (right-to-left)"""
    negative = False
    if exponent == 0:
        return 1
    elif exponent < 0:
        negative = True
        exponent = abs(exponent)
    result = 1
    while exponent > 1:
        if exponent % 2 == 1:
            result *= base
        base **= 2
        exponent //= 2
    return result * base if not negative else 1 / (result * base)

@overload
def modular_pow_left_right(base: int, exponent: int, modulus: int) -> int: ...
@overload
def modular_pow_left_right(base: float, exponent: int, modulus: float) -> float: ...

def modular_pow_left_right(
    base: Union[int, float], exponent: int, modulus: Union[int, float]
) -> Union[int, float]:
    """Modular exponentiation (left-to-right)"""
    if exponent == 0:
        return type(base)(1) % modulus
    if modulus == 1:
        return type(base)(0)
    result = base % modulus
    for bit in f"{exponent:b}"[1:]:
        result = (result**2 * (base if bit == "1" else type(base)(1))) % modulus
    return result % modulus

@overload
def modular_pow_right_left(base: int, exponent: int, modulus: int) -> int: ...
@overload
def modular_pow_right_left(base: float, exponent: int, modulus: float) -> float: ...

def modular_pow_right_left(
    base: Union[int, float], exponent: int, modulus: Union[int, float]
) -> Union[int, float]:
    """Modular exponentiation (right-to-left)"""
    if exponent == 0:
        return 1 % modulus
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 1:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2
    return (result * base) % modulus

def gcd(a: int, b: int) -> int:
    """Greatest common divisor using the Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm to find Bézout coefficients and gcd."""
    x, y = 1, 0
    x1, y1 = 0, 1
    while b:
        q = a // b
        x, x1 = x1, x - q * x1
        y, y1 = y1, y - q * y1
        a, b = b, a % b
    return a, x, y

def multiplicative_inverse(a: int, n: int) -> int:
    """Find the multiplicative inverse of a modulo n using the Extended Euclidean Algorithm."""
    t0, t1 = 0, 1
    r0, r1 = n, a
    while r1 != 0:
        quotient = r0 // r1
        t0, t1 = t1, t0 - quotient * t1
        r0, r1 = r1, r0 - quotient * r1
    if r0 != 1:
        raise ValueError(f"{a} has no inverse modulo {n}")
    return t0 % n

def pascals_triangle_row(n: int, keep_symmetrical: bool = True, keep_ends: bool = True) -> list[int]:
    """Generate the nth row of Pascal's triangle."""
    row = [1]
    previous_value = 1
    for k in range(1, n // 2 + 1):
        current_value = previous_value * (n + 1 - k) // k
        row.append(current_value)
        previous_value = current_value
    if not keep_ends:
        del row[0]
    if not keep_symmetrical:
        return row
    if n % 2:
        return row + row[::-1]
    return row + row[-2::-1]

def pascals_triangle_row_generator(n: int, keep_symmetrical: bool = True, keep_ends: bool = True):
    """Generate the nth row of Pascal's triangle as a generator."""
    if keep_symmetrical:
        if keep_ends:
            stop = n+1
        else:
            stop = n
    else:
        stop = n // 2 + 1
    previous_value = 1
    if keep_ends:
        yield 1
    for k in range(1, stop):
        current_value = previous_value * (n + 1 - k) // k
        yield current_value
        previous_value = current_value

def fibonacci(n: int) -> int:
    """Calculate the nth Fibonacci number using matrix exponentiation."""
    if n in (0, 1):
        return n
    a11, a12, a21, a22 = 1, 1, 1, 0
    b11, b12, b21, b22 = 1, 1, 1, 0
    while n > 1:
        if n % 2 == 1:
            b11, b12, b21, b22 = a11*b11+a12*b21, a11*b12+a12*b22, a21*b11+a22*b21, a21*b12+a22*b22
        a11, a12, a21, a22 = a11*a11+a12*a21, a11*a12+a12*a22, a21*a11+a22*a21, a21*a12+a22*a22
        n //= 2
    return a21*b12+a22*b22

def lucas_sequences_first_kind(n: int, p: int, q: int) -> int:
    """Calculate the nth Lucas sequence of the first kind with parameters p and q."""
    if n == 0:
        return 0
    n -= 1
    a11, a12, a21, a22 = 0, 1, -q, p
    b11, b12, b21, b22 = a11, a12, a21, a22
    while n > 0:
        if n % 2 == 1:
            b11, b12, b21, b22 = a11*b11+a12*b21, a11*b12+a12*b22, a21*b11+a22*b21, a21*b12+a22*b22
        a11, a12, a21, a22 = a11*a11+a12*a21, a11*a12+a12*a22, a21*a11+a22*a21, a21*a12+a22*a22
        n //= 2
    return b11*0+b12*1

def lucas_sequences_second_kind(n: int, p: int, q: int) -> int:
    """Calculate the nth Lucas sequence of the second kind with parameters p and q."""
    if n == 0:
        return 2
    n -= 1
    a11, a12, a21, a22 = 0, 1, -q, p
    b11, b12, b21, b22 = a11, a12, a21, a22
    while n > 0:
        if n % 2 == 1:
            b11, b12, b21, b22 = a11*b11+a12*b21, a11*b12+a12*b22, a21*b11+a22*b21, a21*b12+a22*b22
        a11, a12, a21, a22 = a11*a11+a12*a21, a11*a12+a12*a22, a21*a11+a22*a21, a21*a12+a22*a22
        n //= 2
    return b11*2+b12*p

def lucas_sequences_v1(n: int, p: int, q: int) -> tuple[int, int]:
    """Calculate the nth Lucas sequence with parameters p and q."""
    if n == 0:
        return 0, 2
    n -= 1
    a11, a12, a21, a22 = 0, 1, -q, p
    b11, b12, b21, b22 = a11, a12, a21, a22
    while n > 0:
        if n % 2 == 1:
            b11, b12, b21, b22 = a11*b11+a12*b21, a11*b12+a12*b22, a21*b11+a22*b21, a21*b12+a22*b22
        a11, a12, a21, a22 = a11*a11+a12*a21, a11*a12+a12*a22, a21*a11+a22*a21, a21*a12+a22*a22
        n //= 2
    return b11*0+b12*1, b11*2+b12*p

def lucas_sequences_v2(n: int, p: int, q: int) -> tuple[float, float]:
    """Calculate the nth Lucas sequence with parameters p and q, returning floating-point results."""
    if n == 0:
        return 0, 2
    n -= 1
    a11, a12, a21, a22 = p/2, 1/2, (p**2-4*q)/2, p/2
    b11, b12, b21, b22 = a11, a12, a21, a22
    while n > 0:
        if n % 2 == 1:
            b11, b12, b21, b22 = a11*b11+a12*b21, a11*b12+a12*b22, a21*b11+a22*b21, a21*b12+a22*b22
        a11, a12, a21, a22 = a11*a11+a12*a21, a11*a12+a12*a22, a21*a11+a22*a21, a21*a12+a22*a22
        n //= 2
    return b11*0+b12*2, b21*0+b22*2

def jacobi_symbol(a: int, n: int) -> int:
    """Calculate the Jacobi symbol (a/n) using the law of quadratic reciprocity."""
    assert n > 0 and n % 2 == 1
    a = a % n
    t = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            r = n % 8
            if r == 3 or r == 5:
                t = -t
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            t = -t
        a = a % n
    if n == 1:
        return t
    return 0

def solovay_strassen_test(n: int, k: int) -> bool:
    """Solovay-Strassen primality test."""
    if not n % 2:
        return False
    for _ in range(k):
        a = randint(2, n-1)
        x = jacobi_symbol(a, n)
        if x == 0 or modular_pow_right_left(a, (n-1)//2, n) != (x % n):
            return False
    return True

def miller_rabin_test(n: int, k: int) -> bool:
    """Miller-Rabin primality test."""
    if not n % 2:
        return False
    n1 = n - 1
    s = 0
    while not n1 % 2:
        s += 1
        n1 //= 2
    d = n1
    for _ in range(k):
        a = randint(2, n-2)
        x = modular_pow_right_left(a, d, n)
        for _ in range(s):
            y = x*x % n
            if y == 1 and x != 1 and x != n - 1:
                return False
            x = y
        if y != 1: # type: ignore
            return False
    return True

def fermat_test(n: int, k: int) -> bool:
    """Fermat primality test."""
    assert n > 3
    for _ in range(k):
        a = randint(2, n-2)
        if modular_pow_right_left(a, n-1, n) != 1:
            return False
    return True

def lucas_test(n: int, k: int):
    """Lucas primality test."""
    ...

def is_perfect_square(n: int) -> bool:
    """Check if n is a perfect square."""
    return isqrt(n)**2 == n

def is_perfect_power(n: int) -> bool:
    """Check if n is a perfect power."""
    for b in range(2, floor(log2(n))+1):
        if n**(1/b) % 1 == 0:
            return True
    return False

def multiplicative_order(a: int, n: int) -> int:
    """Find the multiplicative order of a modulo n."""
    for k in range(1, n):
        if modular_pow_right_left(a, k, n) == 1:
            return k
    return -1

def aks_test(n: int) -> bool:
    """AKS primality test."""
    assert n > 1
    # Step 1
    if not is_perfect_power(n):
        # Step 2
        max_k = floor(log2(n)**2)
        max_r = ceil(log2(n)**5)
        next_r, r = True, 2
        while next_r and r < max_r:
            next_r, k = False, 1
            while not next_r and k <= max_k:
                next_r = modular_pow_right_left(n, k, r) == 1
                k += 1
            r += 1
        r -= 1
        # Step 3
        for a in range(r, 1, -1):
            gcd_v = gcd(a, n)
            if gcd_v > 1 and gcd_v < n:
                return False
        # Step 4
        if n < 5690034 and n <= r:
            return True
        # Step 5
        for a in range(1, floor(sqrt(r-1)*log2(n))):
            pass # TODO: polynomial_divison() and polynomial_modulo()
    return True

def aks_test_naive(n: int) -> bool:
    """Naive implementation of the AKS primality test."""
    for a in pascals_triangle_row_generator(n, False, False):
        if a % n:
            return False
    return True

def baillie_psw_test(n: int) -> bool:
    """Baillie-PSW primality test."""
    if n % 2 == 0:
        return n == 2
    if is_perfect_square(n):
        return False
    
    s, d = 0, n - 1
    while not d % 2:
        s += 1
        d //= 2
    x = modular_pow_left_right(2, d, n)
    for _ in range(s):
        y = x*x % n
        if y == 1 and x != 1 and x != n - 1:
            return False
        x = y
    if y != 1: # type: ignore
        return False
    
    d, sign = 5, -1
    while jacobi_symbol(d, n) != -1:
        d = -1 * d + sign * 2
        sign = -sign
    p, q = 1, (1-d) // 4

    delta_n = n
    a11, a12, a21, a22 = 0, 1, -q, p
    b11, b12, b21, b22 = a11, a12, a21, a22
    while delta_n > 0:
        if delta_n % 2 == 1:
            b11, b12, b21, b22 = (a11*b11+a12*b21) % n, (a11*b12+a12*b22) % n, (a21*b11+a22*b21) % n, (a21*b12+a22*b22) % n
        a11, a12, a21, a22 = (a11*a11+a12*a21) % n, (a11*a12+a12*a22) % n, (a21*a11+a22*a21) % n, (a21*a12+a22*a22) % n
        delta_n //= 2
    return b11*0+b12*1 == 0

# def trailing_zeros_supernaive(n: int) -> int:
#     s = 0
#     while not n % 2:
#         s += 1
#         n //= 2
#     return s

# def trailing_zeros_naive(n: int) -> int:
#     n: str = f"{abs(n):b}"
#     return len(n) - len(n.rstrip("0"))

def div2mod(x: int, n: int) -> int:
    """Divide x by 2 modulo n, handling odd and even cases."""
    return ((x + n) >> 1) % n if x & 1 else (x >> 1) % n

def trailing_zeros(n: int) -> int:
    """Count the number of trailing zeros in the binary representation of n."""
    return (n & (~n + 1)).bit_length() - 1

def enhanced_baillie_psw_test(n: int) -> bool:
    """Enhanced Baillie-PSW primality test."""
    if n % 2 == 0:
        return n == 2
    if is_perfect_square(n):
        return False

    # (1) If n is not a strong probable prime to base 2, then n is composite; stop.
    s = (d := n-1) & (~d + 1)
    if s != 0:
        d //= s
        s = s.bit_length() - 1

    x = modular_pow_left_right(2, d, n)
    y = None
    for _ in range(s):
        y = x*x % n
        if y == 1 and x != 1 and x != n - 1:
            return False
        x = y
    if y is None or y != 1:
        return False

    # (2) Choose Lucas parameters with Method A*. If you encounter a D for which (D/n) = 0: if
    #     either |D| < n, or if |D| >= n but n does not divide |D|, then n is composite; stop.
    d, sign = 5, -1
    while jacobi_symbol(d, n) != -1:
        d = -1 * d + sign * 2
        sign = -sign
    p, q = 1, (1-d) // 4
    # if q == -1:
    #    p = q = 5

    # (3) If n is not an slprp(P, Q), then n is composite; stop.
    # (4) If n is not a vprp(P, Q), then n is composite; stop.
    # (5) If n does not satisfy Q^((n+1)/2) ≡ Q * (Q/n) (mod n), then n is composite; stop. 
    #     Otherwise, declare n to be probably prime.
    u, v, q1 = 1, p, q
    for bit in f"{n+1:b}"[1:]:
        q_prev = q
        u, v, q = (u * v) % n, div2mod(v**2 + d*u**2, n), (q**2) % n
        if bit == "1":
            u, v, q = div2mod(p*u + v, n), div2mod(d*u + p*v, n), (q1 * q) % n
    return u == 0 and (v - 2*q1) % n == 0 and q_prev % n == (q1 * jacobi_symbol(q1, n)) % n # type: ignore

def gnfs_estimate_ops(n: int) -> float:
    """Estimate the number of operations required for the General Number Field Sieve (GNFS) for a number n."""
    return exp(cbrt((64/9)*(ln_n:=log(n))*log(ln_n)**2))

def gnfs_estimate_time(n: int, ops_per_sec: float = 1e12) -> str:
    """Estimate the time required for the General Number Field Sieve (GNFS) for a number n."""
    ops = gnfs_estimate_ops(n)
    seconds = ops / ops_per_sec
    return advanced_format_seconds(seconds, auto_detect=True) # type: ignore

def rsa_generate_keys(p: int, q: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """Generate RSA public and private keys from two prime numbers p and q."""
    N = p * q
    phi = (p - 1) * (q - 1)
    while gcd((e := randint(3, phi)), phi) != 1:
        pass
    d = multiplicative_inverse(e, phi)
    return ((e, N), (d, N))

def rsa_generate_keys_with_checks(p: int, q: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """Generate RSA public and private keys from two prime numbers p and q, with security checks."""
    if p == q:
        raise ValueError("p and q must be distinct prime numbers. If not, given N (which by definition is public in RSA), it is trivial to find p=q=√N")
    elif p <= 1 or q <= 1:
        raise ValueError("Both p and q must be greater than 1. Numbers less than or equal to 1 are not prime and cannot be used in cryptographic operations.")
    elif not (baillie_psw_test(p) and baillie_psw_test(q)):
        raise ValueError("Both p and q must be prime numbers. Non-prime numbers could lead to weak encryption keys.")
    elif abs(p-q) < 2**((p * q).bit_length() // 2 - 100):
        # p and q should differ in at least 100 of their most significant bits. (ANSI X9.31 recommendation)
        raise ValueError("The values of p and q are too close. Close primes could make factorization easier and weaken encryption.")
    N = p * q
    phi = (p - 1) * (q - 1)
    while gcd((e := randint(3, phi)), phi) != 1:
        pass
    d = multiplicative_inverse(e, phi)
    if e == d:
        raise ValueError("e and d cannot be equal. If e equals d, the private key can be derived from the public key, which breaks the encryption.")
    return ((e, N), (d, N))

def rsa_encrypt(message: int, public_key: tuple[int, int]) -> int:
    """Encrypt an integer message with the RSA public key (e, N)."""
    e, N = public_key
    return modular_pow_right_left(message, e, N)

def rsa_decrypt(ciphertext: int, private_key: tuple[int, int]) -> int:
    """Decrypt an integer ciphertext with the RSA private key (d, N)."""
    d, N = private_key
    return modular_pow_right_left(ciphertext, d, N)

def chunked_rsa_encrypt(message: int, public_key: tuple[int, int]) -> list[bytes]:
    """Encrypt an integer message using the RSA public key (e, N) in byte chunks."""
    e, N = public_key
    message_bytes = int_to_bytes(message)
    chunk_size = max((N.bit_length() - 1) // 8, 1)  # Ensure chunk < N
    encrypted_chunks: list[bytes] = []
    for i in range(0, len(message_bytes), chunk_size):
        byte_chunk = message_bytes[i:i+chunk_size]
        integer_chunk = int.from_bytes(byte_chunk, 'big')
        zero_padding_length = len(byte_chunk) - (integer_chunk.bit_length()+7)//8
        integer_encrypted = modular_pow_right_left(int.from_bytes(byte_chunk, 'big'), e, N)
        byte_encrypted = b"\x00" * zero_padding_length + int_to_bytes(integer_encrypted, byteorder="big")
        encrypted_chunks.append(byte_encrypted)
        # print(f"Chunk {i//chunk_size}: {byte_chunk} -> {integer_chunk} -> {byte_encrypted} ({len(byte_encrypted)} bytes)")
    return encrypted_chunks

def chunked_rsa_decrypt(ciphertext: list[bytes], private_key: tuple[int, int]) -> int:
    """Decrypt an integer ciphertext with the RSA private key (d, N) in byte chunks."""
    d, N = private_key
    chunk_size = max((N.bit_length() - 1) // 8, 1)
    decrypted_chunks: list[bytes] = []
    for chunk in ciphertext:
        zero_padding_length = len(chunk) - len(chunk := chunk.lstrip(b'\x00'))
        integer_chunk = int.from_bytes(chunk, 'big')
        decrypted = modular_pow_right_left(integer_chunk, d, N)
        chunk_bytes = b"\x00" * zero_padding_length + int_to_bytes(decrypted, chunk_size, 'big').lstrip(b'\x00')
        decrypted_chunks.append(chunk_bytes)
        # print(f"Decrypted chunk: {chunk} -> {integer_chunk} -> {decrypted} -> {chunk_bytes} ({len(chunk_bytes)} bytes)")
    message_bytes = b''.join(decrypted_chunks)
    return int.from_bytes(message_bytes, 'big')

def int_to_str(integer: int, encoding: str = "utf-8", errors: Literal['strict', 'ignore', 'replace'] = "strict") -> str:
    return int_to_bytes(integer).decode(encoding, errors=errors)

def str_to_int(string: str, encoding: str = "utf-8", errors: Literal['strict', 'ignore', 'replace'] = "strict") -> int:
    return int.from_bytes(string.encode(encoding, errors=errors))

def int_to_bytes(integer: int, length: int = 0, byteorder: Literal['little', 'big'] = 'big', signed: bool = False) -> bytes:
    """Converts an integer to its byte representation."""
    if length:
        return integer.to_bytes(length, byteorder, signed=signed)
    return integer.to_bytes((integer.bit_length()+7)//8, byteorder, signed=signed)

if __name__ == "__main__":

    message = str_to_int("\x01\x01\x00\x00The moon reflects pretty bright today. ASDASKdoasdoaksdaksda\x00\x00\x01\x00\x00\x00")

    p, q = rand_prime(3, 2**16), rand_prime(3, 2**16)
    if p and q:
        public_key, private_key = rsa_generate_keys(p, q)
        encrypted_message = chunked_rsa_encrypt(message, public_key)
        decrypted_message = chunked_rsa_decrypt(encrypted_message, private_key)
        
        print(f"Public key:\n\t{public_key}\nPrivate key:\n\t{private_key}\n")
        print(f"\t### Original message:\n{int_to_str(message)}")
        print(f"\t### Original message as integer:\n{message}")
        print(f"\t### Encrypted message:\n{encrypted_message}")
        print(f"\t### Decrypted message:\n{decrypted_message}")
        print(f"\t### Decrypted message as integer:\n{decrypted_message}")
        print(f"\t### Decrypted message as string:\n{int_to_str(decrypted_message)}")
        print(f"\t### Decrypted message as string (repr):\n{repr(int_to_str(decrypted_message))}")
        print(f"\t### Asserting original message equals decrypted message: {message == decrypted_message}")
