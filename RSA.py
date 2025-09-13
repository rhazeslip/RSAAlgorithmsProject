import random
import math

"khyde@cub.uca.edu"

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n<=1:
        return False
    if n<=3:
        return True
    if n%2==0:
        return False
    
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    
    for _ in range(k):
        a = random.randint(2, n-2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
        
    return True

def generate_large_prime(bits = 1024):
    """Generate a large prime number of specified bit length."""

    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Ensure it's odd and has the correct bit length

        if is_prime(num):
            return num
        
def gcd(a, b):
    """Compute the greatest common divisor using Euclid's algorithm."""

    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find the modular inverse."""
    
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y

def mod_inverse(a, m):
    """Find the modular inverse of a modulo m using extended Euclidean Algorithm."""

    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m

def generate_rsa_keys(bits=1024):
    """Generate RSA public and private keys."""
    
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    
    while p == q:
        q = generate_large_prime(bits // 2)

    n = p * q

    phi_n = (p - 1) * (q - 1)
    
    e = 65537  # Common choice for e
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)
    
    d = mod_inverse(e, phi_n)

    public_key = (n, e)
    private_key = (n, d)
    
    return public_key, private_key, p, q

def main():
    print("Generating RSA keys...")
    print("=" * 200)

    public_key, private_key, p, q = generate_rsa_keys(1024)

    n, e = public_key
    n, d = private_key

    print("\nKey Generation Complete")
    print("=" * 200)
    print(f"Prime p (first 50 out of {len(str(p))} digits): {str(p)[:50]}...")
    print(f"Prime q (first 50 out of {len(str(q))} digits): {str(q)[:50]}...")
    print(f"Modulus n (first 50 out of {len(str(n))} digits): {str(n)[:50]}...")
    print(f"Public Exponent e: {e}")
    print(f"Private Exponent d (first 50 out of {len(str(d))} digits): {str(d)[:50]}...")
    print(f"Euler's totient φ(n) (first 50 out of {len(str((p-1)*(q-1)))} digits): {str((p-1)*(q-1))[:50]}...")

    print("\nVerifying key properties:")
    print("=" * 200)

    #Test to make sure e and d are inverses mod φ(n)
    phi_n = (p - 1) * (q - 1)
    verification = (e * d) % phi_n

    if verification == 1:
        print("Key verification successful!")
        print(private_key, "is the private key")
        print(public_key, "is the public key")
    else:
        print("Key verification failed!")
    
if __name__ == "__main__":
    main()