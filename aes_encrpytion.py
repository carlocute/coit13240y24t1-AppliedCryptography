
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt(message, key):
    iv = os.urandom(16)
    aes_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    ciphertext = aes_encryptor.update(padded_data) + aes_encryptor.finalize()
    return iv + ciphertext

def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    aes_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    aes_decryptor = aes_cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = aes_decryptor.update(ciphertext) + aes_decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()
