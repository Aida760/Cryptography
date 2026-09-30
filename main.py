
import os
from modes import *
from experiments import *




KEY = os.urandom(16)
IV = os.urandom(16)
NONCE = os.urandom(8)

TEXT_FILE = "data/sample.txt"
IMAGE_FILE = "data/lena.bmp"


try:
    with open(TEXT_FILE, "rb") as f:
        text_data = f.read()
    print(f"Text file loaded: {len(text_data)} bytes")
except FileNotFoundError:
    print(f"Warning: {TEXT_FILE} not found → using 1MB fallback")
    text_data = b"A" * (1024 * 1024)


print("\nPerformance:\n")

modes = [
    ("ECB", ecb_encrypt, ecb_decrypt, None, None),
    ("CBC", cbc_encrypt, cbc_decrypt, IV, None),
    ("OFB", ofb_encrypt, ofb_decrypt, IV, None),
    ("CTR", ctr_encrypt, ctr_decrypt, None, NONCE)
]

for name, enc, dec, iv, nonce in modes:
    try:
        enc_t, dec_t, enc_speed, dec_speed = measure_performance(enc, dec, KEY, text_data, iv, nonce)
        print(f"{name:4s} | Enc: {enc_t:6.3f}s  Dec: {dec_t:6.3f}s  EncSpeed: {enc_speed:6.1f} MB/s  DecSpeed: {dec_speed:6.1f} MB/s")
    except Exception as e:
        print(f"{name:4s} → ERROR: {str(e)}")


print("\nGenerating encrypted images:\n")

os.makedirs("results", exist_ok=True)

encrypt_image(ecb_encrypt, KEY, IMAGE_FILE, "results/ecb_encrypted.bmp")
encrypt_image(cbc_encrypt, KEY, IMAGE_FILE, "results/cbc_encrypted.bmp", iv=IV)
encrypt_image(ofb_encrypt, KEY, IMAGE_FILE, "results/ofb_encrypted.bmp", iv=IV)
encrypt_image(ctr_encrypt, KEY, IMAGE_FILE, "results/ctr_encrypted.bmp", nonce=NONCE)


print("\nError Propagation Test :\n")

for name, enc, dec, iv, nonce in modes:
    try:
        result = test_error_propagation(enc, dec, KEY, text_data, iv, nonce)
        print(f"{name:4s} → {result}")
    except Exception as e:
        print(f"{name:4s} → ERROR during test: {str(e)}")

print("\nDone. Check 'results/' folder for encrypted images.")