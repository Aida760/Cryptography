# experiments.py
import time
from PIL import Image
from modes import *

def encrypt_image(mode_func, key, input_path, output_path, iv=None, nonce=None):
    try:
        img = Image.open(input_path).convert('RGB')
        img_bytes = img.tobytes()

        if nonce is not None:
            enc_bytes = mode_func(key, img_bytes, nonce)
        elif iv is not None:
            enc_bytes = mode_func(key, img_bytes, iv)
        else:
            enc_bytes = mode_func(key, img_bytes)


        if len(enc_bytes) > len(img_bytes):
            enc_bytes = enc_bytes[:len(img_bytes)]

        enc_img = Image.frombytes('RGB', img.size, enc_bytes)
        enc_img.save(output_path)
        print(f"Saved encrypted image: {output_path}")
    except Exception as e:
        print(f"ERROR in encrypt_image: {str(e)}")

def measure_performance(enc_func, dec_func, key, data, iv=None, nonce=None):

    args = [key, data]
    if nonce is not None: args.append(nonce)
    elif iv is not None: args.append(iv)


    t1 = time.perf_counter()
    ciphertext = enc_func(*args)
    enc_time = time.perf_counter() - t1


    args_dec = [key, ciphertext]
    if nonce is not None: args_dec.append(nonce)
    elif iv is not None: args_dec.append(iv)
    
    t2 = time.perf_counter()
    _ = dec_func(*args_dec)
    dec_time = time.perf_counter() - t2

    size_mb = len(data) / (1024 * 1024)
    return enc_time, dec_time, size_mb/enc_time, size_mb/dec_time

def test_error_propagation(enc_func, dec_func, key, data, iv=None, nonce=None):

    args = [key, data]
    if nonce is not None: args.append(nonce)
    elif iv is not None: args.append(iv)
    ct = enc_func(*args)


    corrupted_ct = bytearray(ct)
    corrupted_ct[5] ^= 0xFF 


    args_dec = [key, bytes(corrupted_ct)]
    if nonce is not None: args_dec.append(nonce)
    elif iv is not None: args_dec.append(iv)

    try:
        recovered = dec_func(*args_dec)
    except ValueError:
        return "Decryption failed (Invalid Padding)"


    min_len = min(len(recovered), len(data))
    diff_bytes = sum(a != b for a, b in zip(recovered[:min_len], data[:min_len]))
    
    result = f"{diff_bytes} bytes different"
    if enc_func in (ecb_encrypt, cbc_encrypt):
        affected_blocks = sum(1 for i in range(0, min_len, 16) if recovered[i:i+16] != data[i:i+16])
        result += f" ({affected_blocks} blocks affected)"
    
    return result