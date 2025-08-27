# DNA-Hybrid Crypto-Benchmark

This repository contains the official source code and benchmarking framework for the research paper:

**"A Secure and Compact Hybrid Encryption Model Combining Adaptive Compression, AES, and DNA-Inspired Key Generation"** by Yusra Al-Najjar, Raghad Abed, and Abdulla Al-Ali.

The project implements a novel hybrid encryption model that integrates adaptive GZIP compression, DNA-based key generation, and AES-CTR encryption to achieve superior storage efficiency without compromising security. This framework allows for the performance benchmarking and security analysis of this proposed method against seven other established encryption algorithms.

## 📋 Table of Contents

1.  [Features](#-features)
2.  [Implemented Algorithms](#-implemented-algorithms)
3.  [Repository Structure](#-repository-structure)
4.  [Installation & Setup](#-installation--setup)
5.  [Usage](#-usage)
    *   [Performance Benchmarking](#1-performance-benchmarking)
    *   [Security Analysis](#2-security-analysis)
6.  [Results](#-results)
7.  [Key Findings from the Paper](#-key-findings-from-the-paper)
8.  [Contributing](#-contributing)
9.  [License](#-license)
10. [Citation](#-citation)
11. [Contact](#-contact)

## ✨ Features

*   **Hybrid Encryption Model:** Implements the proposed method combining adaptive compression, DNA-based key generation, and AES-CTR encryption.
*   **Comprehensive Benchmarking:** Tests 8 encryption algorithms on various file types.
*   **Security Analysis:** Performs statistical tests (NIST SP 800-22) and calculates avalanche effect and entropy.
*   **Conditional Compression:** Intelligently applies GZIP compression only when it reduces overall size.
*   **DNA Cryptography:** Utilizes a nucleotide-to-binary mapping (A=00, C=01, G=10, T=11) for secure key generation.
*   **Extensible Framework:** Easily modifiable to add new algorithms or metrics.

## 🔢 Implemented Algorithms

The framework benchmarks the following encryption methods:

1.  **Symmetric Block Ciphers:**
    *   `AES-128` (CBC mode)
    *   `DES` (CBC mode)
    *   `Blowfish` (using AES as a reference implementation)
2.  **Symmetric Stream Cipher:**
    *   `ChaCha20`
3.  **One-Time Pads:**
    *   `OTP` (Standard One-Time Pad)
    *   `DNA-OTP` (DNA-based One-Time Pad)
4.  **Compression Hybrid:**
    *   `AES-128+GZIP` (Compress then encrypt)
5.  **Proposed Method:**
    *   `Proposed` (Adaptive Compression + DNA-AES-CTR)

## 📁 Repository Structure




## ⚙️ Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/usra7/dna-hybrid-crypto-benchmark.git
    cd dna-hybrid-crypto-benchmark
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Add your test files:**
    *   Place the files you want to benchmark into the `test_files/` directory. The paper used a diverse set including `.rar`, `.doc`, `.png`, `.pdf`, `.docx`, and `.exe` files.

## 🚀 Usage

### 1. Performance Benchmarking

This script measures encryption/decryption time, throughput, ciphertext size, and expansion ratio.

```bash
python benchmark.py
python security_analysis.py
Input: Generates random data for analysis.

Output: Results are saved to comprehensive_security_analysis.csv.

Metrics: Shannon Entropy, Avalanche Effect (%), Monobit Test (p-value), Byte Distribution Test (p-value), Runs Test (p-value).

@article{alnajjar2025secure,
  title={A Secure and Compact Hybrid Encryption Model Combining Adaptive Compression, AES, and DNA-Inspired Key Generation},
  author={Al-Najjar, Yusra and Abed, Raghad and Al-Ali, Abdulla},
  journal={Journal of Systems Architecture},
  year={2025},
  publisher={Elsevier}
}
