from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
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
