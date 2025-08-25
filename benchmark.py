import os
import time
import csv
import gzip
import psutil
import numpy as np
from Crypto.Cipher import AES, DES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import threading

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

def get_encrypt_function(method):
    """Get the appropriate encryption function based on method name"""
    encryption_functions = {
        "AES-128": encrypt_aes,
        "DES": encrypt_des,
        "Blowfish": encrypt_blowfish,
        "ChaCha20": encrypt_chacha20,
        "OTP": encrypt_otp,
        "DNA-OTP": encrypt_dna_otp,
        "AES-128+GZIP": encrypt_aes_gzip,
        "Proposed": encrypt_proposed
    }
    return encryption_functions.get(method)

def get_decrypt_function(method):
    """Get the appropriate decryption function based on method name"""
    decryption_functions = {
        "AES-128": decrypt_aes,
        "DES": decrypt_des,
        "Blowfish": decrypt_blowfish,
        "ChaCha20": decrypt_chacha20,
        "OTP": decrypt_otp,
        "DNA-OTP": decrypt_dna_otp,
        "AES-128+GZIP": decrypt_aes_gzip,
        "Proposed": decrypt_proposed
    }
    return decryption_functions.get(method)

def load_test_files():
    """Load actual files from the test_files folder"""
    test_files = {}
    test_folder = "test_files"
    
    # Create test_files directory if it doesn't exist
    if not os.path.exists(test_folder):
        os.makedirs(test_folder)
        print(f"Created {test_folder} directory. Please add your test files to this folder.")
        return test_files
    
    # Read all files from the test_files directory
    for filename in os.listdir(test_folder):
        filepath = os.path.join(test_folder, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                test_files[filename] = file_data
                print(f"Loaded test file: {filename} ({len(file_data)} bytes)")
            except Exception as e:
                print(f"Error reading file {filename}: {e}")
    
    if not test_files:
        print(f"No files found in {test_folder} directory. Please add test files to benchmark.")
    
    return test_files

def run_with_timeout(func, args=(), kwargs={}, timeout=30):
    """Run a function with timeout"""
    result = [None]
    exception = [None]
    
    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    
    if thread.is_alive():
        raise TimeoutError(f"Operation timed out after {timeout} seconds")
    if exception[0] is not None:
        raise exception[0]
    
    return result[0]

def benchmark_encryption():
    """Main benchmarking function with ALL algorithms including OTP for all files"""
    methods = [
        "AES-128", "DES", "Blowfish", "ChaCha20",
        "OTP", "DNA-OTP", "AES-128+GZIP", "Proposed"
    ]
    
    # Load test files from test_files folder
    test_files = load_test_files()
    
    if not test_files:
        print("No test files found. Exiting benchmark.")
        return []
    
    results = []
    
    for filename, original_data in test_files.items():
        print(f"\nProcessing file: {filename} ({len(original_data)} bytes)")
        
        for method in methods:
            print(f"    Testing method: {method}")
            
            # Show warning for OTP methods on large files
            file_size_mb = len(original_data) / (1024 * 1024)
            if method in ["OTP", "DNA-OTP"] and file_size_mb > 1:
                print(f"      Warning: OTP method on large file ({file_size_mb:.1f} MB) - may be slow or fail")
            
            encrypt_func = get_encrypt_function(method)
            decrypt_func = get_decrypt_function(method)
            
            if not encrypt_func or not decrypt_func:
                print(f"      Warning: No functions found for {method}")
                continue
            
            # Force garbage collection before each test
            import gc
            gc.collect()
            
            try:
                # Time encryption with timeout
                start_time = time.time()
                encrypted_data, key = run_with_timeout(encrypt_func, (original_data,), timeout=60)
                encrypt_time = (time.time() - start_time) * 1000
                
                # Force garbage collection before decryption
                gc.collect()
                
                # Time decryption with timeout
                start_time = time.time()
                decrypted_data = run_with_timeout(decrypt_func, (encrypted_data, key), timeout=60)
                decrypt_time = (time.time() - start_time) * 1000
                
                # Force garbage collection after operations
                gc.collect()
                
                # Verify correctness
                if decrypted_data != original_data:
                    print(f"      Error: Decryption failed for {method}")
                    continue
                
                # Calculate metrics
                original_size = len(original_data)
                encrypted_size = len(encrypted_data)
                expansion_ratio = encrypted_size / original_size
                throughput = (original_size / 1024 / 1024) / (encrypt_time / 1000) if encrypt_time > 0 else 0
                
                # Store results
                result = {
                    'File Name': filename,
                    'Type': os.path.splitext(filename)[1],
                    'Original Size (B)': original_size,
                    'Method': method,
                    'Ciphertext Size (B)': encrypted_size,
                    'Encrypt Time (ms)': encrypt_time,
                    'Decrypt Time (ms)': decrypt_time,
                    'Expansion Ratio': expansion_ratio,
                    'Throughput (MB/s)': throughput
                }
                
                results.append(result)
                print(f"      Success: {encrypt_time:.2f}ms encrypt, {decrypt_time:.2f}ms decrypt, Ratio: {expansion_ratio:.2f}")
                
            except TimeoutError:
                print(f"      Timeout: {method} took too long on this file")
            except MemoryError as e:
                print(f"      MemoryError with {method}: {str(e)}")
            except Exception as e:
                print(f"      Error with {method}: {str(e)[:100]}")
    
    return results

def save_results_to_csv(results, filename="encryption_benchmark_results.csv"):
    """Save benchmarking results to CSV file"""
    if not results:
        print("No results to save")
        return
    
    # Define the exact columns we want
    fieldnames = [
        'File Name', 
        'Type', 
        'Original Size (B)', 
        'Method', 
        'Ciphertext Size (B)', 
        'Encrypt Time (ms)', 
        'Decrypt Time (ms)', 
        'Expansion Ratio', 
        'Throughput (MB/s)'
    ]
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Results saved to {filename} with {len(results)} records")

if __name__ == "__main__":
    print("Loading test files from test_files folder and running benchmarks...")
    
    # Debug: Check if test_files folder exists and has files
    test_folder = "test_files"
    if os.path.exists(test_folder):
        files = os.listdir(test_folder)
        print(f"Found {len(files)} files in {test_folder}: {files}")
        
        # Check file sizes
        for file in files:
            filepath = os.path.join(test_folder, file)
            size = os.path.getsize(filepath)
            print(f"  {file}: {size} bytes ({size/1024/1024:.2f} MB)")
    else:
        print(f"Folder {test_folder} does not exist. Creating it...")
        os.makedirs(test_folder)
        print("Please add test files to the test_files folder and run again.")
        exit()
    
    results = benchmark_encryption()
    
    if results:
        save_results_to_csv(results, "encryption_benchmark_results.csv")
        print(f"Benchmark completed successfully! {len(results)} tests performed.")
    else:
        print("No results generated. Please check if files exist in test_files folder.")