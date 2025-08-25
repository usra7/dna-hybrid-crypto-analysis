# helpers.py
import os
import zlib
import math
import time
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import struct

# Constants
BLOCK_SIZE = 16

# DNA key functions (keep these the same)
def generate_dna_key(length=32):
    dna_bases = ['A', 'C', 'G', 'T']
    dna_key = ''.join([dna_bases[b % 4] for b in os.urandom(length)])
    return dna_key.encode('utf-8')

def dna_to_binary(dna_key):
    if isinstance(dna_key, bytes):
        dna_str = dna_key.decode('utf-8')
    else:
        dna_str = str(dna_key)
    
    mapping = {'A': 0, 'C': 1, 'G': 2, 'T': 3}
    key_bytes = bytearray()
    
    for char in dna_str:
        if char in mapping:
            key_bytes.append(mapping[char])
        else:
            key_bytes.append(ord(char) % 4)
    
    return bytes(key_bytes)

# Simplified encryption/decryption functions that work correctly
def encrypt_otp_simple(data):
    """Simple OTP encryption that works reliably"""
    key = get_random_bytes(len(data))
    encrypted = bytes(a ^ b for a, b in zip(data, key))
    return encrypted, key

def decrypt_otp_simple(encrypted_data, key):
    """Simple OTP decryption"""
    return bytes(a ^ b for a, b in zip(encrypted_data, key))

def encrypt_dna_otp_simple(data):
    """Simple DNA-OTP encryption that works reliably"""
    dna_key = generate_dna_key(32)
    binary_key = dna_to_binary(dna_key)
    
    # Extend key if needed
    if len(binary_key) < len(data):
        binary_key = (binary_key * (len(data) // len(binary_key) + 1))[:len(data)]
    
    encrypted = bytes(a ^ b for a, b in zip(data, binary_key))
    return encrypted, dna_key

def decrypt_dna_otp_simple(encrypted_data, dna_key):
    """Simple DNA-OTP decryption"""
    binary_key = dna_to_binary(dna_key)
    
    # Extend key if needed
    if len(binary_key) < len(encrypted_data):
        binary_key = (binary_key * (len(encrypted_data) // len(binary_key) + 1))[:len(encrypted_data)]
    
    return bytes(a ^ b for a, b in zip(encrypted_data, binary_key))

def encrypt_proposed_simple(data):
    """Simple Proposed method encryption that works reliably"""
    # Generate DNA key
    dna_key = generate_dna_key(32)
    binary_key = dna_to_binary(dna_key)
    
    # Ensure proper key length for AES
    if len(binary_key) < 16:
        binary_key = binary_key.ljust(16, b'\0')[:16]
    else:
        binary_key = binary_key[:16]
    
    # Compress then encrypt
    compressed_data = zlib.compress(data)
    cipher = AES.new(binary_key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(compressed_data, BLOCK_SIZE))
    
    # Return IV + encrypted data and the DNA key
    return iv + encrypted_data, dna_key

def decrypt_proposed_simple(encrypted_data, dna_key):
    """Simple Proposed method decryption"""
    binary_key = dna_to_binary(dna_key)
    
    # Ensure proper key length for AES
    if len(binary_key) < 16:
        binary_key = binary_key.ljust(16, b'\0')[:16]
    else:
        binary_key = binary_key[:16]
    
    # Extract IV and decrypt
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    cipher = AES.new(binary_key, AES.MODE_CBC, iv)
    decrypted_compressed = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    return zlib.decompress(decrypted_compressed)

# Helper functions
def generate_test_data(size=1024):
    return os.urandom(size)

def measure_time(func, *args, **kwargs):
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    return result, (end_time - start_time) * 1000

def get_memory_usage():
    return 0.0