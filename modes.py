# modes.py
from aes import aes_encrypt_block, aes_decrypt_block

BLOCK_SIZE = 16



def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    if not data:
        return b''
    pad_len = data[-1]
    if pad_len > BLOCK_SIZE or pad_len == 0:
        raise ValueError("Invalid padding")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))



def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    padded_data = pad(plaintext)
    ciphertext = b""
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i + BLOCK_SIZE]
        ciphertext += aes_encrypt_block(key, block)
    return ciphertext

def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    plaintext = b""
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        plaintext += aes_decrypt_block(key, block)
    return unpad(plaintext)



def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    padded_data = pad(plaintext)
    ciphertext = b""
    prev = iv
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i + BLOCK_SIZE]
        xored = xor_bytes(block, prev)
        enc = aes_encrypt_block(key, xored)
        ciphertext += enc
        prev = enc
    return ciphertext

def cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    plaintext = b""
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = aes_decrypt_block(key, block)
        plaintext += xor_bytes(dec, prev)
        prev = block
    return unpad(plaintext)



def ofb_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    output = b""
    stream = iv
    for i in range(0, len(plaintext), BLOCK_SIZE):
        stream = aes_encrypt_block(key, stream)
        chunk = plaintext[i:i + BLOCK_SIZE]
        output += xor_bytes(chunk, stream[:len(chunk)])
    return output

def ofb_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    return ofb_encrypt(key, ciphertext, iv)



def ctr_encrypt(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    output = b""
    counter = 0
    for i in range(0, len(plaintext), BLOCK_SIZE):
        counter_block = nonce + counter.to_bytes(8, byteorder="big")
        keystream = aes_encrypt_block(key, counter_block)
        chunk = plaintext[i:i + BLOCK_SIZE]
        output += xor_bytes(chunk, keystream[:len(chunk)])
        counter += 1
    return output

def ctr_decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    return ctr_encrypt(key, ciphertext, nonce)