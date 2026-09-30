AES Block Cipher Modes & Security Analysis

A complete Python implementation of the Advanced Encryption Standard (AES-128) operating modes (ECB, CBC, OFB, CTR) and performance security analysis.

Project Structure
- `aes.py`: Core AES-128 algorithm (SubBytes, ShiftRows, MixColumns, AddRoundKey, and Decryption inverse functions).
- `modes.py`: Implementation of ECB, CBC, OFB, and CTR cipher modes.
- `main.py`: Primary execution script for running tests.
- `data/`: Sample input datasets (e.g., `lena.bmp`, `sample.txt`).
- `results/`: Encrypted output image results across various modes.

 Experimental Findings
- ECB Mode: Shows severe pattern leakage when encrypting structured data (like BMP images) because identical plaintext blocks encrypt to identical ciphertext blocks.
- CBC / OFB / CTR Modes: Completely obscure underlying data patterns by leveraging Initialization Vectors (IVs) or keystreams.
- Error Propagation: Errors in ECB and CBC affect entire 16-byte blocks or propagate to subsequent blocks, whereas errors in CTR and OFB remain strictly localized.
