"""
Encryption and Hashing Module
-----------------------------
Handles AES encryption/decryption (CBC mode) and SHA-256 hashing for secure file transfer.
"""



from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

KEY = b'BTUCompNetProjct'  # 16 byte - 128 bit key

# Encrypts the given byte data using AES.
def encrypt_file(data: bytes) -> bytes:
    # data : Raw byte data to encrypt

    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted  # Encrypted data with IV prepended

# Decrypts AES encrypted data that includes a prepended IV.
def decrypt_file(data: bytes) -> bytes:
    # data: Encrypted data (IV + ciphertext)

    iv = data[:16] # first 16 bytes are iv
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:]), AES.block_size) # Original decrypted data

# Computes the SHA-256 hash of the input byte data.
def sha256_hash(data: bytes) -> str:
    # data: Input byte data
    return hashlib.sha256(data).hexdigest() # Hexadecimal hash string
