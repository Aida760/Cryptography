from aes import AES

def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

class ECB:
    def __init__(self, key: bytes):
        self.aes = AES(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = pad(plaintext)
        res = b""
        for i in range(0, len(padded), 16):
            res += self.aes.encrypt_block(padded[i:i+16])
        return res

    def decrypt(self, ciphertext: bytes) -> bytes:
        res = b""
        for i in range(0, len(ciphertext), 16):
            res += self.aes.decrypt_block(ciphertext[i:i+16])
        return unpad(res)

class CBC:
    def __init__(self, key: bytes, iv: bytes):
        self.aes = AES(key)
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = pad(plaintext)
        res = b""
        prev = self.iv
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            xored = bytes(b1 ^ b2 for b1, b2 in zip(block, prev))
            enc = self.aes.encrypt_block(xored)
            res += enc
            prev = enc
        return res

    def decrypt(self, ciphertext: bytes) -> bytes:
        res = b""
        prev = self.iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            dec = self.aes.decrypt_block(block)
            res += bytes(b1 ^ b2 for b1, b2 in zip(dec, prev))
            prev = block
        return unpad(res)

class OFB:
    def __init__(self, key: bytes, iv: bytes):
        self.aes = AES(key)
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        res = b""
        curr_iv = self.iv
        for i in range(0, len(plaintext), 16):
            curr_iv = self.aes.encrypt_block(curr_iv)
            block = plaintext[i:i+16]
            res += bytes(b1 ^ b2 for b1, b2 in zip(block, curr_iv))
        return res

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)

class CTR:
    def __init__(self, key: bytes, nonce: bytes):
        self.aes = AES(key)
        self.nonce = nonce

    def encrypt(self, plaintext: bytes) -> bytes:
        res = b""
        counter = 0
        for i in range(0, len(plaintext), 16):
            ctr_block = self.nonce + counter.to_bytes(8, 'big')
            keystream = self.aes.encrypt_block(ctr_block)
            block = plaintext[i:i+16]
            res += bytes(b1 ^ b2 for b1, b2 in zip(block, keystream))
            counter += 1
        return res

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)
