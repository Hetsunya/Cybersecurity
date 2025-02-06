import random

def key_schedule(seed: int, length: int):
    random.seed(seed)
    return [random.randint(0, 255) for _ in range(length)]

def encrypt(text: str, key: int) -> bytes:
    byte_data = text.encode('utf-8')
    keystream = key_schedule(key, len(byte_data))
    encrypted = bytes((b ^ k) for b, k in zip(byte_data, keystream))
    return encrypted

def decrypt(encrypted: bytes, key: int) -> str:
    keystream = key_schedule(key, len(encrypted))
    decrypted = bytes((b ^ k) for b, k in zip(encrypted, keystream))
    return decrypted.decode('utf-8', errors='ignore')

if __name__ == "__main__":
    message = "Hello, World!"
    key = 12345
    enc = encrypt(message, key)
    print("Encrypted:", enc.hex())
    dec = decrypt(enc, key)
    print("Decrypted:", dec)
