import math

def encrypt(text: str, columns: int) -> str:
    rows = math.ceil(len(text) / columns)
    grid = ['' for _ in range(columns)]

    for i, char in enumerate(text):
        grid[i % columns] += char

    return ''.join(grid)

def decrypt(encrypted: str, columns: int) -> str:
    rows = math.ceil(len(encrypted) / columns)
    grid = ['' for _ in range(rows)]

    index = 0
    for col in range(columns):
        for row in range(rows):
            if index < len(encrypted):
                grid[row] += encrypted[index]
                index += 1

    return ''.join(grid)

if __name__ == "__main__":
    message = "HelloWorld"
    columns = 4
    enc = encrypt(message, columns)
    print("Encrypted:", enc)
    dec = decrypt(enc, columns)
    print("Decrypted:", dec)
