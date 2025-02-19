import tkinter as tk
from sha import sha256  # Импортируем функцию sha256 из sha.py

# Функция для хэширования текста и отображения результата
def hash_text():
    input_text = text_entry.get()  # Получаем текст из поля ввода
    result = sha256(input_text)    # Хэшируем текст
    result_label.config(text=f"SHA-256 хэш: {result}")  # Отображаем результат

# Создаем главное окно
root = tk.Tk()
root.title("SHA-256 Хэширование")

# Создаем метку и поле ввода для текста
text_label = tk.Label(root, text="Введите текст для хэширования:")
text_label.pack(pady=10)

text_entry = tk.Entry(root, width=50)
text_entry.pack(pady=5)

# Создаем кнопку для запуска хэширования
hash_button = tk.Button(root, text="Хэшировать", command=hash_text)
hash_button.pack(pady=10)

# Создаем метку для отображения результата
result_label = tk.Label(root, text="SHA-256 хэш: ")
result_label.pack(pady=10)

# Запуск интерфейса
root.mainloop()
