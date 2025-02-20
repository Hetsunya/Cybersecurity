class IDEA:
    def __init__(self, key):
        self._keys = None
        self.gen_keys(key)  # Генерация ключей для шифрования/расшифрования

    # Умножение по модулю 0x10001
    def mul_mod(self, a, b):
        assert 0 <= a <= 0xFFFF  # Проверка, что a и b в допустимом диапазоне
        assert 0 <= b <= 0xFFFF

        # Если a или b равны 0, заменяем на 0x10000, т.к. IDEA использует 0x10000 как специальное значение
        if a == 0:
            a = 0x10000
        if b == 0:
            b = 0x10000

        r = (a * b) % 0x10001  # Модульное умножение

        if r == 0x10000:
            r = 0  # Убираем лишнюю величину, если результат равен 0x10000

        assert 0 <= r <= 0xFFFF
        return r

    # Сложение по модулю 0x10000
    def add_mod(self, a, b):
        return (a + b) % 0x10000  # Модульное сложение

    # Аддитивная инверсия по модулю 0x10000
    def add_inv(self, key):
        u = (0x10000 - key) % 0xFFFF  # Находим обратное по аддитивной операции
        assert 0 <= u <= 0x10000 - 1
        return u

    # Мультипликативная инверсия
    def mul_inv(self, key):
        a = 0x10000 + 1
        if key == 0:
            return 0  # Если ключ равен 0, возвращаем 0
        else:
            x = 0
            y = 0
            x1 = 0
            x2 = 1
            y1 = 1
            y2 = 0
            while key > 0:
                q = a // key  # Вычисление частного
                r = a - q * key  # Остаток
                x = x2 - q * x1  # Коэффициент для x
                y = y2 - q * y1  # Коэффициент для y
                a = key
                key = r
                x2 = x1
                x1 = x
                y2 = y1
                y1 = y
            d = a
            x = x2
            y = y2
            return y

    # Основной этап шифрования / расшифрования для одного раунда
    def round(self, p1, p2, p3, p4, keys):
        k1, k2, k3, k4, k5, k6 = keys

        # Шаг 1
        p1 = self.mul_mod(p1, k1)
        p4 = self.mul_mod(p4, k4)
        p2 = self.add_mod(p2, k2)
        p3 = self.add_mod(p3, k3)

        # Шаг 2
        x = p1 ^ p3  # XOR между p1 и p3
        t0 = self.mul_mod(k5, x)  # Умножение по модулю
        x = p2 ^ p4
        x = self.add_mod(t0, x)  # Сложение с результатом
        t1 = self.mul_mod(k6, x)
        t2 = self.add_mod(t0, t1)

        # Шаг 3
        p1 = p1 ^ t1
        p4 = p4 ^ t2
        a = p2 ^ t2
        p2 = p3 ^ t1
        p3 = a

        return p1, p2, p3, p4

    # Генерация всех ключей для всех раундов шифрования
    def gen_keys(self, key):
        assert 0 <= key < (1 << 128)  # Проверка на диапазон 128-битного ключа
        modulus = 1 << 128

        sub_keys = []
        for i in range(9 * 6):
            sub_keys.append((key >> (112 - 16 * (i % 8))) % 0x10000)
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % modulus  # Циклический сдвиг

        keys = []
        for i in range(9):
            round_keys = sub_keys[6 * i: 6 * (i + 1)]
            keys.append(tuple(round_keys))
        self._keys = tuple(keys)  # Сохраняем все ключи

    # Шифрование текста
    def encrypt(self, plain):
        p1 = (plain >> 48) & 0xFFFF
        p2 = (plain >> 32) & 0xFFFF
        p3 = (plain >> 16) & 0xFFFF
        p4 = plain & 0xFFFF

        # Все 8 раундов шифрования
        for i in range(8):
            keys = self._keys[i]
            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

        # Финальная трансформация
        k1, k2, k3, k4, x, y = self._keys[8]
        y1 = self.mul_mod(p1, k1)
        y2 = self.add_mod(p3, k2)
        y3 = self.add_mod(p2, k3)
        y4 = self.mul_mod(p4, k4)

        encrypted = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4

        return encrypted

    # Расшифровка текста
    def decrypt(self, encrypted):
        p1 = (encrypted >> 48) & 0xFFFF
        p2 = (encrypted >> 32) & 0xFFFF
        p3 = (encrypted >> 16) & 0xFFFF
        p4 = encrypted & 0xFFFF

        # Первый раунд расшифрования
        keys = self._keys[8]
        k1 = self.mul_inv(keys[0])
        if k1 < 0:
            k1 = 0x10000 + 1 + k1
        k2 = self.add_inv(keys[1])
        k3 = self.add_inv(keys[2])
        k4 = self.mul_inv(keys[3])
        if k4 < 0:
            k4 = 0x10000 + 1 + k4
        keys = self._keys[7]
        k5 = keys[4]
        k6 = keys[5]
        keys = [k1, k2, k3, k4, k5, k6]
        p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

        # Остальные раунды
        for i in range(1, 8):
            keys = self._keys[8 - i]
            k1 = self.mul_inv(keys[0])
            if k1 < 0:
                k1 = 0x10000 + 1 + k1
            k2 = self.add_inv(keys[2])
            k3 = self.add_inv(keys[1])
            k4 = self.mul_inv(keys[3])
            if k4 < 0:
                k4 = 0x10000 + 1 + k4
            keys = self._keys[7 - i]
            k5 = keys[4]
            k6 = keys[5]
            keys = [k1, k2, k3, k4, k5, k6]
            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

        # Финальная трансформация
        keys = self._keys[0]
        k1 = self.mul_inv(keys[0])
        if k1 < 0:
            k1 = 0x10000 + 1 + k1
        k2 = self.add_inv(keys[1])
        k3 = self.add_inv(keys[2])
        k4 = self.mul_inv(keys[3])
        if k4 < 0:
            k4 = 0x10000 + 1 + k4
        y1 = self.mul_mod(p1, k1)
        y2 = self.add_mod(p3, k2)
        y3 = self.add_mod(p2, k3)
        y4 = self.mul_mod(p4, k4)
        decrypted = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return decrypted

if __name__ == "__main__":
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    cipher = IDEA(key)

    a = 0x1234
    b = 0x5678
    result_mul = cipher.mul_mod(a, b)
    print(f"Результат умножения {a:#06x} * {b:#06x} по модулю: {result_mul:#06x}")

    a = 0x1234
    b = 0x5678
    result_add = cipher.add_mod(a, b)
    print(f"Результат сложения {a:#06x} + {b:#06x} по модулю: {result_add:#06x}")

    key = 0x1234
    result_add_inv = cipher.add_inv(key)
    print(f"Аддитивная инверсия для {key:#06x}: {result_add_inv:#06x}")

    key = 0x5678
    result_mul_inv = cipher.mul_inv(key)
    print(f"Мультипликативная инверсия для {key:#06x}: {result_mul_inv:#06x}")

    plain = 0x0123456789abcdef
    encrypted = cipher.encrypt(plain)
    decrypted = cipher.decrypt(encrypted)

    print(f"Исходный текст: {plain:#018x}")
    print(f"Зашифрованный текст: {encrypted:#018x}")
    print(f"Расшифрованный текст: {decrypted:#018x}")

    assert plain == decrypted, "Ошибка: расшифрованный текст не совпадает с исходным!"
