import os
import numpy as np
import pandas as pd
from scipy.stats import chi2
from math import erf, sqrt
from crypto_utils import *  # Import all encryption functions

def encrypt_for_analysis(encrypt_func, data):
    """Wrapper function for security analysis that returns only ciphertext"""
    encrypted_data, key = encrypt_func(data)
    return encrypted_data

def shannon_entropy(data):
    """Calculate Shannon entropy of data"""
    if len(data) == 0:
        return 0
    entropy = 0
    data = bytearray(data)
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return entropy

def monobit_test(bit_sequence):
    """Frequency (Monobit) Test from NIST SP 800-22"""
    n = len(bit_sequence)
    if n == 0:
        return 0.0
    
    # Count ones (bit = 1)
    ones_count = sum(bit_sequence)
    zeros_count = n - ones_count
    s = abs(ones_count - zeros_count) / np.sqrt(n)
    
    # p-value = erfc(s / sqrt(2))
    p_value = erf(s / np.sqrt(2))
    return p_value

def byte_distribution_test(data):
    """Test for uniform distribution of byte values (0-255)"""
    if len(data) == 0:
        return 0.0
    
    # Count frequency of each byte value
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    # Chi-squared test for uniform distribution
    expected = len(data) / 256
    chi_square = sum((count - expected) ** 2 / expected for count in byte_counts)
    
    # p-value from chi-squared distribution with 255 degrees of freedom
    p_value = 1 - chi2.cdf(chi_square, 255)
    return p_value

def runs_test(bit_sequence):
    """Runs Test from NIST SP 800-22"""
    n = len(bit_sequence)
    if n == 0:
        return 0.0
    
    # Compute proportion of ones
    ones = sum(bit_sequence)
    pi = ones / n
    
    # Check if test is applicable
    if abs(pi - 0.5) >= (2 / np.sqrt(n)):
        return 0.0  # Test not applicable
    
    # Count number of runs (both 0s and 1s)
    runs = 1
    for i in range(1, n):
        if bit_sequence[i] != bit_sequence[i-1]:
            runs += 1
    
    # Compute test statistic
    numerator = abs(runs - 2 * n * pi * (1 - pi))
    denominator = 2 * np.sqrt(2 * n) * pi * (1 - pi)
    z = numerator / denominator
    
    # p-value = erfc(z / sqrt(2))
    p_value = erf(z / np.sqrt(2))
    return p_value

def avalanche_effect(encrypt_func, data, trials=100):
    """Calculate avalanche effect by flipping single bits"""
    if len(data) == 0:
        return 0, 0
    
    avalanche_effects = []
    data = bytearray(data)
    
    for _ in range(min(trials, len(data) * 8)):
        # Create copy and flip a random bit
        modified_data = bytearray(data)
        byte_pos = np.random.randint(0, len(data))
        bit_pos = np.random.randint(0, 8)
        modified_data[byte_pos] ^= (1 << bit_pos)
        
        # Encrypt both original and modified
        original_cipher = encrypt_for_analysis(encrypt_func, bytes(data))
        modified_cipher = encrypt_for_analysis(encrypt_func, bytes(modified_data))
        
        # Calculate percentage of changed bits
        changed_bits = 0
        total_bits = len(original_cipher) * 8
        
        for b1, b2 in zip(original_cipher, modified_cipher):
            xor_result = b1 ^ b2
            changed_bits += bin(xor_result).count('1')
        
        percentage_changed = (changed_bits / total_bits) * 100
        avalanche_effects.append(percentage_changed)
    
    avg_avalanche = np.mean(avalanche_effects)
    std_avalanche = np.std(avalanche_effects)
    
    return avg_avalanche, std_avalanche

def analyze_encryption_method(encrypt_func, method_name, data_sizes=[1024, 8192, 65536]):
    """Analyze security properties of an encryption method"""
    results = []
    
    for size in data_sizes:
        print(f"  Analyzing {method_name} with {size} bytes...")
        
        try:
            # Generate random test data
            test_data = os.urandom(size)
            
            # Encrypt the data
            ciphertext = encrypt_for_analysis(encrypt_func, test_data)
            
            # Calculate entropy
            original_entropy = shannon_entropy(test_data)
            encrypted_entropy = shannon_entropy(ciphertext)
            
            # Convert to bit sequence for statistical tests
            bit_sequence = []
            for byte in ciphertext:
                bit_sequence.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
            bit_sequence = np.array(bit_sequence)
            
            # Run statistical tests
            monobit_p = monobit_test(bit_sequence)
            byte_p = byte_distribution_test(ciphertext)
            runs_p = runs_test(bit_sequence)
            
            # Calculate avalanche effect
            avg_avalanche, std_avalanche = avalanche_effect(encrypt_func, test_data, trials=50)
            
            result = {
                'Data_Size': size,
                'Original_Entropy': original_entropy,
                'Encrypted_Entropy': encrypted_entropy,
                'Avalanche_Effect_%': avg_avalanche,
                'Avalanche_Std_Dev': std_avalanche,
                'Monobit_Test_p': monobit_p,
                'Byte_Distribution_p': byte_p,
                'Runs_Test_p': runs_p,
                'Status': 'PASS' if all(p > 0.01 for p in [monobit_p, byte_p]) else 'FAIL'
            }
            
            results.append(result)
            
        except Exception as e:
            error_result = {
                'Data_Size': size,
                'Original_Entropy': 0,
                'Encrypted_Entropy': 0,
                'Avalanche_Effect_%': 0,
                'Avalanche_Std_Dev': 0,
                'Monobit_Test_p': 0,
                'Byte_Distribution_p': 0,
                'Runs_Test_p': 0,
                'Status': f'ERROR: {str(e)}'
            }
            results.append(error_result)
    
    return results

def main():
    """Main security analysis function"""
    # Define encryption methods to test
    methods = {
        'AES-128': encrypt_aes,
        'AES-128+GZIP': encrypt_aes_gzip,
        'ChaCha20': encrypt_chacha20,
        'DES': encrypt_des,
        'Blowfish': encrypt_blowfish,
        'OTP': encrypt_otp,
        'DNA-OTP': encrypt_dna_otp,
        'Proposed_Method': encrypt_proposed
    }
    
    data_sizes = [1024, 8192, 65536]  # 1KB, 8KB, 64KB
    all_results = []
    
    print("Starting security analysis...")
    
    for method_name, encrypt_func in methods.items():
        print(f"==================================================")
        print(f"Analyzing {method_name}...")
        
        results = analyze_encryption_method(encrypt_func, method_name, data_sizes)
        
        for result in results:
            result['Method'] = method_name
            all_results.append(result)
    
    # Create DataFrame and save results
    df = pd.DataFrame(all_results)
    df.to_csv('comprehensive_security_analysis.csv', index=False)
    
    # Print summary
    print("==================================================")
    print("Analysis Summary:")
    print("==================================================")
    summary = df.groupby('Method').agg({
        'Encrypted_Entropy': 'mean',
        'Avalanche_Effect_%': 'mean',
        'Monobit_Test_p': 'mean',
        'Status': 'first'
    }).round(6)
    
    print(summary)
    print(f"\nDetailed results saved to 'comprehensive_security_analysis.csv'")

if __name__ == "__main__":
    main()