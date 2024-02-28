import random
import timeit

def is_prime_miller_rabin(n, k=5):   #Check if a number is prime using the Miller-Rabin test.

    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
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

def generate_prime(bits):   #Generate a random prime number with the specified number of bits.
   
    while True:
        num = random.getrandbits(bits)
        if is_prime_miller_rabin(num):
            return num

def mod_inverse(a, m):       #Calculate the modular inverse using the Extended Euclidean Algorithm.

    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keypair(bits):
    
    p =  generate_prime(bits)
    q =  generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # commonly used value for e(2^16 +1)
    d = mod_inverse(e, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)

    public_key = (n, e)
    private_key = (n, d, p, q, dp, dq)
    return public_key, private_key

def encrypt(public_key, message):  # Encrypt a message using RSA.

    n, e = public_key
    text = pow(message, e, n)


    return text

def decrypt_without_CRT(private_key, ciphertext): # Decrypt a message using RSA.
    n, d, p, q, dp, dq  = private_key
   # message = pow(ciphertext, d, n)
    message = square_multiply_algo(ciphertext, d, n)
    return  message

def decrypt_with_crt(private_key, ciphertext):   #Decrypt using RSA with Chinese Remainder Theorem.
   
    n, d, p, q, dp, dq = private_key

    # Compute dp and dq
    dp = d % (p - 1)
    dq = d % (q - 1)

    # Compute u and v fulfilling 1 = u · p + v · q
    _, u, v = extended_gcd(p, q)

    # Compute sigp = m^dp mod p and sigq = m^dq mod q
    #sigp = pow(ciphertext, dp, p)
    #sigq = pow(ciphertext, dq, q)

    sigp = square_multiply_algo(ciphertext, dp, p)
    sigq = square_multiply_algo(ciphertext, dq, q)
    # Combine sigp and sigq using CRT
    sig = (u * p * sigq + v * q * sigp) % n

    return sig


def extended_gcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def square_multiply_algo(x, y, n):
    exp = bin(y)[2:]  # Convert y to binary and remove the '0b' prefix
    value = 1
    #range(len(exp))
    for i in exp:
        value = (value ** 2) % n 
        if i == '1':
            value = (value * x) % n
           
    return value




def measure_decrypt_with_crt():# Function to measure the time for decrypt_integer with CRT
    decrypted_message_with_crt = decrypt_with_crt(private_key, ciphertext)


def measure_decrypt_without_CRT(): # Function to measure the time for decrypt_integer
    decrypted_message_without_crt = decrypt_without_CRT(private_key, ciphertext)


# Example usage:
bits = 2048
public_key, private_key = generate_keypair(bits)
message = 98765432123456789
ciphertext = encrypt(public_key, message)
decrypted_message_with_crt = decrypt_with_crt(private_key, ciphertext)
decrypted_message_without_crt = decrypt_without_CRT(private_key, ciphertext)

#print("public key:", public_key)
print("Private key:", private_key)


print("Original message:", message)
print("Ciphertext:", ciphertext)
print("Decrypted message with CRT:", decrypted_message_with_crt)
print("Decrypted message without CRT:", decrypted_message_without_crt)

time_with_crt = timeit.timeit(measure_decrypt_with_crt, number=500)
print("Time for decrypt_with_crt:", time_with_crt)

# Measure time for decrypt_integer
time_without_crt = timeit.timeit(measure_decrypt_without_CRT, number=500)
print("Time for decrypt_integer:", time_without_crt)

# strategy for convincing the professor that our implementation is secure, is test vectors provided for RSA  by NSA or BSI ( not sure of the names) 
# testvectors which we have used https://asecuritysite.com/encryption/getprimen


