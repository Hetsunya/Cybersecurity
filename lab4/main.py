import tkinter as tk
from tkinter import messagebox
from rsa import *

# Основной интерфейс
class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Шифрование")

        # Интерфейс
        self.label_message = tk.Label(root, text="Сообщение:")
        self.label_message.pack()

        self.entry_message = tk.Entry(root, width=50)
        self.entry_message.pack()

        self.label_public_key = tk.Label(root, text="Публичный ключ:")
        self.label_public_key.pack()
        self.entry_public_key = tk.Entry(root, width=50)
        self.entry_public_key.pack()

        self.label_private_key = tk.Label(root, text="Приватный ключ:")
        self.label_private_key.pack()
        self.entry_private_key = tk.Entry(root, width=50)
        self.entry_private_key.pack()

        self.button_generate_keys = tk.Button(root, text="Перегенерировать ключи", command=self.generate_new_keys)
        self.button_generate_keys.pack()

        self.button_encrypt = tk.Button(root, text="Зашифровать", command=self.encrypt_message)
        self.button_encrypt.pack()

        self.button_decrypt = tk.Button(root, text="Расшифровать", command=self.decrypt_message)
        self.button_decrypt.pack()

        self.label_encrypted = tk.Label(root, text="Зашифрованное сообщение:")
        self.label_encrypted.pack()

        self.entry_encrypted = tk.Entry(root, width=50)
        self.entry_encrypted.pack()

        self.label_decrypted = tk.Label(root, text="Расшифрованное сообщение:")
        self.label_decrypted.pack()

        self.entry_decrypted = tk.Entry(root, width=50)
        self.entry_decrypted.pack()

        # Генерация ключей
        self.generate_new_keys()

    def generate_new_keys(self):
        self.public_key, self.private_key = generate_keys()
        self.update_key_fields()

    def update_key_fields(self):
        self.entry_public_key.delete(0, tk.END)
        self.entry_public_key.insert(0, ','.join(map(str, self.public_key)))

        self.entry_private_key.delete(0, tk.END)
        self.entry_private_key.insert(0, ','.join(map(str, self.private_key)))

    def encrypt_message(self):
        message = self.entry_message.get()
        if not message:
            messagebox.showerror("Ошибка", "Введите сообщение для шифрования.")
            return
        try:
            public_key = tuple(map(int, self.entry_public_key.get().split(',')))
            ciphertext = encrypt(message, public_key)
            self.entry_encrypted.delete(0, tk.END)
            self.entry_encrypted.insert(0, ','.join(map(str, ciphertext)))
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {e}")

    def decrypt_message(self):
        encrypted_message = self.entry_encrypted.get()
        if not encrypted_message:
            messagebox.showerror("Ошибка", "Введите зашифрованное сообщение.")
            return
        try:
            private_key = tuple(map(int, self.entry_private_key.get().split(',')))
            ciphertext = list(map(int, encrypted_message.split(',')))
            decrypted_message = decrypt(ciphertext, private_key)
            self.entry_decrypted.delete(0, tk.END)
            self.entry_decrypted.insert(0, decrypted_message)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка расшифровки: {e}")

# Запуск приложения
if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
