import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Not used in this file but imported
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag # Needed for AES decryption error handling
import os

# --- Caesar Cipher ---
def caesar_cipher(text, shift, mode='encrypt'):
    """
    Applies the Caesar cipher to the given text.
    Args:
        text (str): The input string to encrypt or decrypt.
        shift (int): The number of positions to shift each letter.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text.
    """
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            if mode == 'encrypt':
                shifted_char_code = start + (ord(char) - start + shift) % 26
            elif mode == 'decrypt':
                # Added +26 for correct negative modulo behavior in Python
                shifted_char_code = start + (ord(char) - start - shift + 26) % 26
            result += chr(shifted_char_code)
        else:
            result += char
    return result

# --- Vigenere Cipher ---
def vigenere_cipher(text, key, mode='encrypt'):
    """
    Applies the Vigenere cipher to the given text.
    Args:
        text (str): The input string to encrypt or decrypt.
        key (str): The keyword for the Vigenere cipher.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text.
    """
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            key_shift = ord(key[key_index % len(key)]) - ord('A')

            if mode == 'encrypt':
                shifted_char_code = start + (ord(char) - start + key_shift) % 26
            elif mode == 'decrypt':
                # Added +26 for correct negative modulo behavior in Python
                shifted_char_code = start + (ord(char) - start - key_shift + 26) % 26

            result += chr(shifted_char_code)
            key_index += 1
        else:
            result += char
    return result

# --- RSA Encryption ---
def generate_rsa_key_pair():
    """Generates a new RSA public and private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key_pem_or_str, plaintext):
    """
    Encry pts plaintext using an RSA public key.
    Args:
        public_key_pem_or_str (bytes or str): The RSA public key in PEM format (bytes or string).
        plaintext (str): The data to encrypt.
    Returns:
        str: The base64-encoded encrypted ciphertext (string).
    """
    # Convert PEM key string to bytes if needed
    if isinstance(public_key_pem_or_str, str):
        public_key_pem = public_key_pem_or_str.encode('utf-8')
    else:
        public_key_pem = public_key_pem_or_str

    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Return base64 string for easy session storage/transfer
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(private_key_pem_or_str, ciphertext_b64_or_bytes):
    """
    Decrypts ciphertext using an RSA private key.
    Args:
        private_key_pem_or_str (bytes or str): The RSA private key in PEM format (bytes or string).
        ciphertext_b64_or_bytes (bytes or str): The base64-encoded ciphertext (string) or raw bytes.
    Returns:
        str: The decrypted plaintext.
    """
    # Convert PEM key string to bytes if needed
    if isinstance(private_key_pem_or_str, str):
        private_key_pem = private_key_pem_or_str.encode('utf-8')
    else:
        private_key_pem = private_key_pem_or_str

    # Decode base64 ciphertext to bytes if needed
    if isinstance(ciphertext_b64_or_bytes, str):
        ciphertext = base64.b64decode(ciphertext_b64_or_bytes)
    else:
        ciphertext = ciphertext_b64_or_bytes

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

# --- AES Encryption ---
def generate_aes_key_and_iv():
    """Generates a random AES key (256-bit) and a random IV."""
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV for AES-CBC
    return key, iv

def aes_encrypt(key_b64_or_bytes, iv_b64_or_bytes, plaintext):
    """
    Encry pts plaintext using AES in CBC mode.
    Args:
        key_b64_or_bytes (bytes or str): The AES key (raw bytes or base64 string).
        iv_b64_or_bytes (bytes or str): The initialization vector (raw bytes or base64 string).
        plaintext (str): The data to encrypt.
    Returns:
        str: The base64-encoded encrypted ciphertext (string).
    """
    # Decode base64 key/iv to bytes if needed
    key = base64.b64decode(key_b64_or_bytes) if isinstance(key_b64_or_bytes, str) else key_b64_or_bytes
    iv = base64.b64decode(iv_b64_or_bytes) if isinstance(iv_b64_or_bytes, str) else iv_b64_or_bytes

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # PKCS7 padding to ensure plaintext is a multiple of block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # Return base64 string for easy session storage/transfer
    return base64.b64encode(ciphertext).decode('utf-8')

def aes_decrypt(key_b64_or_bytes, iv_b64_or_bytes, ciphertext_b64_or_bytes):
    """
    Decrypts ciphertext using AES in CBC mode.
    Args:
        key_b64_or_bytes (bytes or str): The AES key (raw bytes or base64 string).
        iv_b64_or_bytes (bytes or str): The initialization vector (raw bytes or base64 string).
        ciphertext_b64_or_bytes (bytes or str): The base64-encoded ciphertext (string) or raw bytes.
    Returns:
        str: The decrypted plaintext.
    """
    # Decode base64 key/iv/ciphertext to bytes if needed
    key = base64.b64decode(key_b64_or_bytes) if isinstance(key_b64_or_bytes, str) else key_b64_or_bytes
    iv = base64.b64decode(iv_b64_or_bytes) if isinstance(iv_b64_or_bytes, str) else iv_b64_or_bytes
    ciphertext = base64.b64decode(ciphertext_b64_or_bytes) if isinstance(ciphertext_b64_or_bytes, str) else ciphertext_b64_or_bytes

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        # Unpad the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except InvalidTag: # Specifically for authenticated modes, but good to include for general robustness
        raise ValueError("Invalid ciphertext or key/IV for AES decryption (InvalidTag).")
    except Exception as e:
        # Catch other potential decryption errors (e.g., incorrect padding due to wrong key/IV)
        raise ValueError(f"AES decryption failed: {e}")