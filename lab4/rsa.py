import random


def isprime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


# Генерация простого числа
def generate_prime(bits=8):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate


# Расширенный алгоритм Евклида для нахождения обратного элемента
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


# Находим обратное число по модулю
def mod_inverse(e, phi):
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('Обратное число не существует')
    else:
        return x % phi


# Генерация ключей
def generate_keys(bits=8):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1) #функция эйлера

    e = 65537  # часто выбирается это значение
    d = mod_inverse(e, phi)

    # Публичный ключ (e, n), приватный ключ (d, n)
    print(f"p: {p}, q: {q}, n: {n}, phi: {phi}, d: {d}")
    return (e, n), (d, n)


# Шифрование
def encrypt(message, pub_key):
    e, n = pub_key
    return [pow(ord(char), e, n) for char in message]


# Расшифровка
def decrypt(ciphertext, priv_key):
    d, n = priv_key
    return ''.join([chr(pow(char, d, n)) for char in ciphertext])


# Тест
if __name__ == "__main__":
    public_key, private_key = generate_keys()
    print("Публичный ключ:", public_key)
    print("Приватный ключ:", private_key)

    message = "Hello, RSA!"
    print("\nИсходное сообщение:", message)

    ciphertext = encrypt(message, public_key)
    print("Зашифрованное сообщение:", ciphertext)

    decrypted_message = decrypt(ciphertext, private_key)
    print("Расшифрованное сообщение:", decrypted_message)
