def encrypt(text: str, shift: int) -> str:
    encrypted = []
    for char in text:
        # Сдвигаем символы с использованием их Unicode кодов
        encrypted.append(chr((ord(char) + shift) % 1114112))  # Для всех символов Unicode
    return ''.join(encrypted)

def decrypt(text: str, shift: int) -> str:
    return encrypt(text, -shift)

if __name__ == "__main__":
    message = "Привет, мир! 123 kjhsfksdhkfjk12368?>><>KJHJGJSf"
    shift = 3
    enc = encrypt(message, shift)
    print("Encrypted:", enc)
    dec = decrypt(enc, shift)
    print("Decrypted:", dec)
