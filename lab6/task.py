import platform
import uuid
from sha import sha256

def get_system_info():
    system_info = {}
    # Получаем информацию о системе
    system_info['system'] = platform.system()  # Операционная система
    system_info['node_name'] = platform.node()  # Имя устройства в сети
    system_info['release'] = platform.release()  # Версия ОС
    system_info['version'] = platform.version()  # Полная версия ОС
    system_info['machine'] = platform.machine()  # Архитектура процессора
    system_info['processor'] = platform.processor()  # Модель процессора

    # Получаем MAC-адрес сетевой карты
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
    system_info['mac_address'] = mac

    return system_info


def generate_hash():
    system_info = get_system_info()
    system_info_string = ''.join(f"{key}: {value}\n" for key, value in system_info.items())
    return sha256(system_info_string)


def save_hash_to_file(hash_value, filename="system_hash.txt"):
    with open(filename, "w") as f:
        f.write(hash_value)


def load_hash_from_file(filename="system_hash.txt"):
    try:
        with open(filename, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None  # Если файл не найден, возвращаем None


def check_license():
    # Получаем сохраненный хеш из файла
    saved_hash = load_hash_from_file()
    # Генерируем текущий хеш для системы
    current_hash = generate_hash()

    if saved_hash is None:
        # Если файл не существует, это первый запуск, сохраняем текущий хеш
        save_hash_to_file(current_hash)
        print("Первый запуск. Хеш сохранен.")
    elif saved_hash != current_hash:
        # Если хеши не совпадают, значит изменения в аппаратном/программном обеспечении
        print("Нелегальное использование программы!")
    else:
        # Если хеши совпадают, программа легальна
        print("Лицензия подтверждена. Программа работает.")


if __name__ == "__main__":
    check_license()
