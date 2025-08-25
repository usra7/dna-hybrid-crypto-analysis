import os
import gzip
import time
import psutil
import numpy as np
from Crypto.Cipher import AES, DES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib

# Binary-to-Nucleotide Mapping (Table I from the paper)
NUCLEOTIDE_MAP = {
    'A': '00',
    'C': '01', 
    'G': '10',
    'T': '11'
}

REVERSE_NUCLEOTIDE_MAP = {v: k for k, v in NUCLEOTIDE_MAP.items()}

def generate_dna_key(length=64):
    """Generate a random DNA sequence for key generation"""
    nucleotides = ['A', 'C', 'G', 'T']
    return ''.join(np.random.choice(nucleotides) for _ in range(length))

def dna_to_binary(dna_sequence):
    """Convert DNA sequence to binary string using the mapping"""
    binary_str = ''
    for nucleotide in dna_sequence:
        binary_str += NUCLEOTIDE_MAP[nucleotide]
    return binary_str

def binary_to_bytes(binary_str):
    """Convert binary string to bytes"""
    # Pad with zeros to make length multiple of 8
    padding = (8 - len(binary_str) % 8) % 8
    binary_str = binary_str + '0' * padding
    
    bytes_data = bytearray()
    for i in range(0, len(binary_str), 8):
        byte_str = binary_str[i:i+8]
        bytes_data.append(int(byte_str, 2))
    
    return bytes(bytes_data)

def should_compress(data, threshold=20):
    """Determine if compression should be applied"""
    if len(data) <= threshold:
        return False
    
    # Try compressing and check if beneficial
    compressed = gzip.compress(data, compresslevel=9)
    return len(compressed) + 9 < len(data)

# Encryption functions for different algorithms
def encrypt_aes(data, key=None):
    """AES-128 encryption in CBC mode"""
    if key is None:
        key = get_random_bytes(16)
    
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes, key

def decrypt_aes(encrypted_data, key):
    """AES-128 decryption"""
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def encrypt_des(data, key=None):
    """DES encryption"""
    if key is None:
        key = get_random_bytes(8)
    
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES.block_size))
    return cipher.iv + ct_bytes, key

def decrypt_des(encrypted_data, key):
    """DES decryption"""
    iv = encrypted_data[:8]
    ct = encrypted_data[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    return pt

def encrypt_blowfish(data, key=None):
    """Blowfish encryption (using AES as substitute)"""
    # Using AES since Blowfish isn't in standard Crypto library
    return encrypt_aes(data, key)

def decrypt_blowfish(encrypted_data, key):
    """Blowfish decryption"""
    return decrypt_aes(encrypted_data, key)

def encrypt_chacha20(data, key=None):
    """ChaCha20 encryption"""
    if key is None:
        key = get_random_bytes(32)
    
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ct_bytes = cipher.encrypt(data)
    return nonce + ct_bytes, key

def decrypt_chacha20(encrypted_data, key):
    """ChaCha20 decryption"""
    nonce = encrypted_data[:12]
    ct = encrypted_data[12:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    pt = cipher.decrypt(ct)
    return pt

def encrypt_otp(data, key=None):
    """One-Time Pad encryption"""
    if key is None:
        key = get_random_bytes(len(data))
    
    ct_bytes = bytes(a ^ b for a, b in zip(data, key))
    return ct_bytes, key

def decrypt_otp(encrypted_data, key):
    """One-Time Pad decryption"""
    return encrypt_otp(encrypted_data, key)[0]

def encrypt_dna_otp(data, key=None):
    """DNA-based OTP encryption"""
    if key is None:
        # Generate random DNA sequence as long as the data
        dna_key = generate_dna_key(len(data) * 4)  # 2 bits per nucleotide, 4 nucleotides per byte
    else:
        dna_key = key
    
    # Convert DNA to binary key
    binary_key = dna_to_binary(dna_key)
    key_bytes = binary_to_bytes(binary_key)
    
    # Ensure key is at least as long as data
    if len(key_bytes) < len(data):
        key_bytes = key_bytes * (len(data) // len(key_bytes) + 1)
    key_bytes = key_bytes[:len(data)]
    
    # Perform OTP encryption
    ct_bytes = bytes(a ^ b for a, b in zip(data, key_bytes))
    return ct_bytes, dna_key

def decrypt_dna_otp(encrypted_data, key):
    """DNA-based OTP decryption"""
    return encrypt_dna_otp(encrypted_data, key)[0]

def encrypt_aes_gzip(data, key=None):
    """AES-128 with GZIP compression first"""
    compressed_data = gzip.compress(data, compresslevel=9)
    return encrypt_aes(compressed_data, key)

def decrypt_aes_gzip(encrypted_data, key):
    """AES-128 with GZIP decompression"""
    decrypted = decrypt_aes(encrypted_data, key)
    return gzip.decompress(decrypted)

def encrypt_proposed(data, key=None):
    """Proposed hybrid encryption method"""
    # Step 1: Conditional compression
    if should_compress(data):
        compressed_data = gzip.compress(data, compresslevel=9)
        compression_flag = b'\x01'
        data_to_encrypt = compressed_data
    else:
        compression_flag = b'\x00'
        data_to_encrypt = data
    
    # Step 2: DNA-based key generation
    if key is None:
        dna_sequence = generate_dna_key(64)  # 64 nucleotides = 128 bits
        binary_key = dna_to_binary(dna_sequence)
        key_bytes = binary_to_bytes(binary_key)[:16]  # Take first 16 bytes for AES-128
    else:
        key_bytes = key
        dna_sequence = None
    
    # Step 3: Generate nonce for CTR mode
    nonce = get_random_bytes(8)
    
    # Step 4: AES-CTR encryption
    cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(data_to_encrypt)
    
    # Step 5: Format output
    output = compression_flag + nonce + ciphertext
    
    return output, key_bytes if dna_sequence is None else dna_sequence

def decrypt_proposed(encrypted_data, key):
    """Proposed hybrid decryption method"""
    # Extract components
    compression_flag = encrypted_data[0:1]
    nonce = encrypted_data[1:9]
    ciphertext = encrypted_data[9:]
    
    # Convert DNA key to bytes if necessary
    if isinstance(key, str):  # DNA sequence
        binary_key = dna_to_binary(key)
        key_bytes = binary_to_bytes(binary_key)[:16]
    else:  # Already bytes
        key_bytes = key
    
    # AES-CTR decryption
    cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
    decrypted_data = cipher.decrypt(ciphertext)
    
    # Decompress if needed
    if compression_flag == b'\x01':
        original_data = gzip.decompress(decrypted_data)
    else:
        original_data = decrypted_data
    
    return original_data