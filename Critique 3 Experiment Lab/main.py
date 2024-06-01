
import time
from encryption import generate_keys, encrypt_message, decrypt_message, sign_message, verify_signature
from encryption import dh_generate_keys, dh_generate_shared_key

# 計時裝飾器
def timed(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"{func.__name__} took {end_time - start_time:.4f} seconds")
        return result
    return wrapper

# Alice 和 Bob 的 RSA 密鑰對
@timed
def generate_alice_keys():
    return generate_keys()

@timed
def generate_bob_keys():
    return generate_keys()

alice_private_key, alice_public_key = generate_alice_keys()
bob_private_key, bob_public_key = generate_bob_keys()

# 印出 Alice 和 Bob 的公鑰和私鑰
print("\n{:=^100}\n".format("Result : "))
print("Alice's Public Key:")
print(alice_public_key.decode())
print("Alice's Private Key:")
print(alice_private_key.decode())

print("Bob's Public Key:")
print(bob_public_key.decode())
print("Bob's Private Key:")
print(bob_private_key.decode())

# Alice 加密訊息並簽署
message = "This is a test message."

@timed
def encrypt_for_bob(public_key, message):
    return encrypt_message(public_key, message)

@timed
def decrypt_for_bob(private_key, encrypted_message):
    return decrypt_message(private_key, encrypted_message)

@timed
def sign_by_alice(private_key, message):
    return sign_message(private_key, message)

@timed
def verify_by_alice(public_key, message, signature):
    return verify_signature(public_key, message, signature)
print("\n{:=^100}\n".format("Split Line"))
encrypted_message = encrypt_for_bob(bob_public_key, message)
print(f"Encrypted message: {encrypted_message}")

decrypted_message = decrypt_for_bob(bob_private_key, encrypted_message)
print(f"Decrypted message: {decrypted_message}")

print("\n{:=^100}\n".format("Split Line"))

signature = sign_by_alice(alice_private_key, message)
print(f"Signature: {signature}")

is_valid = verify_by_alice(alice_public_key, message, signature)
print(f"Signature valid: {is_valid}")
print("\n{:=^100}\n".format("Split Line"))
# Alice 和 Bob 的 Diffie-Hellman 密鑰交換
@timed
def dh_keys_for_alice():
    return dh_generate_keys()

@timed
def dh_keys_for_bob():
    return dh_generate_keys()

p, g, alice_private_key_dh, alice_public_key_dh = dh_keys_for_alice()
_, _, bob_private_key_dh, bob_public_key_dh = dh_keys_for_bob()

@timed
def dh_shared_key_for_alice(private_key, public_key, p):
    return dh_generate_shared_key(private_key, public_key, p)

@timed
def dh_shared_key_for_bob(private_key, public_key, p):
    return dh_generate_shared_key(private_key, public_key, p)

shared_key_alice = dh_shared_key_for_alice(alice_private_key_dh, bob_public_key_dh, p)
shared_key_bob = dh_shared_key_for_bob(bob_private_key_dh, alice_public_key_dh, p)

print("\n{:=^100}\n".format("Split Line"))

print(f"Shared key (Alice): {shared_key_alice}")
print(f"Shared key (Bob): {shared_key_bob}")

print(f"Shared keys match: {shared_key_alice == shared_key_bob}")
