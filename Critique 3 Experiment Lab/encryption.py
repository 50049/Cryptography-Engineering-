from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random.random import getrandbits
from Crypto.Util.number import long_to_bytes, bytes_to_long

# RSA 加密和簽名
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

def sign_message(private_key, message):
    private_key = RSA.import_key(private_key)
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, message, signature):
    public_key = RSA.import_key(public_key)
    h = SHA256.new(message.encode('utf-8'))
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Diffie-Hellman 密鑰交換
def dh_generate_keys():
    p = 23  # 共有素數 (在實際應用中應使用更大的素數)
    g = 5   # 共有基數
    private_key = getrandbits(16)  # 私有密鑰 (在實際應用中應使用更大的隨機數)
    public_key = pow(g, private_key, p)
    return p, g, private_key, public_key

def dh_generate_shared_key(private_key, other_public_key, p):
    shared_key = pow(other_public_key, private_key, p)
    return long_to_bytes(shared_key)
