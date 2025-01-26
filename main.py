from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random

def diffie_hellman_large_params(q, alpha):
    # Remove newlines and convert hex strings to integers
    # Just to help storing the parameters with newlines to show the whole thing
    q = int(q.replace("\n", "").replace(" ", ""), 16)
    alpha = int(alpha.replace("\n", "").replace(" ", ""), 16)

    # Step 1: Alice and Bob pick private keys
    alice_private = random.randint(1, q - 1)
    bob_private = random.randint(1, q - 1)

    # Step 2: Compute public keys
    alice_public = pow(alpha, alice_private, q)
    bob_public = pow(alpha, bob_private, q)

    # Step 3: Compute shared secret
    alice_shared_secret = pow(bob_public, alice_private, q)
    bob_shared_secret = pow(alice_public, bob_private, q)

    if alice_shared_secret != bob_shared_secret:
        raise ValueError("Key mismatch: Alice and Bob computed different shared secrets!")

    # Step 4: Hash shared secret
    #convert shared key to bytes in big endian
    # add 7 to ensure remainder bits are rounded up to nearest byte then floor divide gives number of bytes
    # digest returns hash result as a byte sequence
    # we are told AES requires a 128-bit key, so we will truncate to 16 bytes
    shared_key = SHA256.new(
        data=alice_shared_secret.to_bytes((alice_shared_secret.bit_length() + 7) // 8, byteorder='big')).digest()[:16]

    return shared_key


def aes_encrypt(key, plaintext):
    iv = get_random_bytes(16)  # Generate random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext


def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext.decode()

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

def modular_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError(f"No modular inverse exists for e={e} and phi={phi}.")
    return x % phi

def rsa_keygen(bits=2048):
    # Step 1: Generate two large prime numbers, p and q
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    # Step 2: Compute n and phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    # Step 3: Choose public exponent e
    e = 65537  # Commonly used public exponent
    # Step 4: Compute private key d using the custom modular inverse function
    d = modular_inverse(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    # Convert plaintext to an integer
    plaintext_int = bytes_to_long(plaintext.encode())
    # Encrypt: c = m^e mod n
    ciphertext = pow(plaintext_int, e, n)
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    # Decrypt: m = c^d mod n
    plaintext_int = pow(ciphertext, d, n)
    # Convert integer back to plaintext
    plaintext = long_to_bytes(plaintext_int).decode()
    return plaintext

# IETF-recommended parameters
q = """
B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61
6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF
ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0
A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
"""

alpha = """
A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31
266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4
D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A
D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
"""

# Perform Diffie-Hellman Key Exchange with large parameters
shared_key = diffie_hellman_large_params(q, alpha)

# Encrypt and decrypt messages
message_alice_to_bob = "Hi Bob!"
ciphertext = aes_encrypt(shared_key, message_alice_to_bob)
decrypted_message = aes_decrypt(shared_key, ciphertext)

print(f"Alice's message: {message_alice_to_bob}")
print(f"Ciphertext (sent to Bob): {ciphertext.hex()}")
print(f"Decrypted message (at Bob): {decrypted_message}")

"""PART 2"""
print(f"\n--------------------------------------------------------------\n")
#Mallory intercepts and replaces with 1
qnum = int(q.replace("\n", "").replace(" ", ""), 16)
alphanum = int(alpha.replace("\n", "").replace(" ", ""), 16)
bob_pick = random.randint(1, qnum - 1)
alice_pick = random.randint(1, qnum - 1)
mallory_mod = qnum
print(f"Bob picks : {bob_pick}")
print(f"Alice picks : {alice_pick}")
bob_key = pow(alphanum, bob_pick, qnum)
alice_key = pow(alphanum, alice_pick, qnum)
s = pow(mallory_mod, bob_pick, qnum)
shared = SHA256.new(
        data=s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')).digest()[:16]
print(f"Bob's key: {bob_key}")
print(f"Alice's key: {alice_key}")
message = "I sure hope nobody can read this Bob."
encrypted = aes_encrypt(shared, message)
print(f"Alice sends: {message}")
print(f"Encrypted message: {encrypted}")

#Since Mallory intercepted Ya and Yb and replaced it with q, s will always be 0 regardless of what
#Bob and Alice's keys are since q^x % q is always 0
malloryskey = SHA256.new(bytes(0)).digest()[:16]
decrypted_message = aes_decrypt(malloryskey, encrypted)
print(f"Mallory reads: {decrypted_message}")
print(f"\n--------------------------------------------------------------\n")
"""TAMPERING WITH ALPHA"""
tamperedalpha = 1

bob_pick = random.randint(1, qnum - 1)
alice_pick = random.randint(1, qnum - 1)
print(f"Bob picks : {bob_pick}")
print(f"Alice picks : {alice_pick}")
bob_key = pow(tamperedalpha, bob_pick, qnum)
alice_key = pow(tamperedalpha, alice_pick, qnum)
s = pow(bob_key, bob_pick, qnum)
shared = SHA256.new(
        data=s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')).digest()[:16]
print(f"Bob's key: {bob_key}")
print(f"Alice's key: {alice_key}")
print(f"S: {s}")
message = "I sure hope nobody can read this Bob."
encrypted = aes_encrypt(shared, message)
print(f"Alice sends: {message}")
print(f"Encrypted message: {encrypted}")
mallory = 1
malloryskey2 = SHA256.new(data=mallory.to_bytes((s.bit_length() + 7) // 8, byteorder='big')).digest()[:16]
decrypted_message2 = aes_decrypt(malloryskey2, encrypted)
print(f"Mallory reads: {decrypted_message2}")
#By setting the alpha to 1 Mallory knows that both bob and alices keys are going to be 1 from there
#she knows that s is also going to be 1. If she sets alpha to q bobs, alices, and the
#shared keys will be 0. By setting alpha to q-1 she knows that the keys will
#either be equal to 1, or q -1. From there she can decrypt the messages

print(f"\n--------------------------------------------------------------\n")
# Generate RSA keys
public_key, private_key = rsa_keygen(bits=2048)
plaintext = "Hi, Bob!"
# Encrypt the plaintext
ciphertext = rsa_encrypt(public_key, plaintext)
print(f"Ciphertext: {ciphertext}")
# Decrypt the ciphertext
decrypted_message = rsa_decrypt(private_key, ciphertext)
print(f"Decrypted message: {decrypted_message}")
# Verify the decryption
assert plaintext == decrypted_message, "Decryption failed!"

