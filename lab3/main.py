import tkinter as tk
from tkinter import messagebox
import random
from IDEA import IDEA

class IdeaApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IDEA Encryption")

        # Поля для ввода
        self.text_label = tk.Label(root, text="Текст")
        self.text_label.pack()
        self.text_entry = tk.Entry(root, width=50)
        self.text_entry.pack()

        self.encrypted_label = tk.Label(root, text="Шифровка")
        self.encrypted_label.pack()
        self.encrypted_entry = tk.Entry(root, width=50)
        self.encrypted_entry.pack()

        self.decrypted_label = tk.Label(root, text="Расшифровка")
        self.decrypted_label.pack()
        self.decrypted_entry = tk.Entry(root, width=50)
        self.decrypted_entry.pack()

        self.key_label = tk.Label(root, text="Ключ")
        self.key_label.pack()
        self.key_entry = tk.Entry(root, width=50)
        self.key_entry.pack()

        # Кнопки
        self.generate_key_button = tk.Button(root, text="Генерировать ключ", command=self.generate_key)
        self.generate_key_button.pack()

        self.encrypt_button = tk.Button(root, text="Зашифровать", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Расшифровать", command=self.decrypt)
        self.decrypt_button.pack()

    def generate_key(self):
        key = random.getrandbits(128)
        key_hex = hex(key)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key_hex)

    def split_into_blocks(self, text):
        byte_data = text.encode('utf-8')
        blocks = []
        for i in range(0, len(byte_data), 8):
            block = byte_data[i:i+8]
            if len(block) < 8:
                block = block.ljust(8, b'\x00')  # Добавляем 0, если блок меньше 8 байт
            blocks.append(int.from_bytes(block, byteorder='big'))
        return blocks

    def join_blocks(self, blocks):
        byte_data = b''.join(block.to_bytes(8, byteorder='big') for block in blocks)
        return byte_data

    def encrypt(self):
        text = self.text_entry.get()
        key = self.key_entry.get()
        if not text or not key:
            messagebox.showerror("Ошибка", "Введите текст и ключ")
            return
        try:
            key = int(key, 16)
            idea = IDEA(key)

            # Разбиваем текст на блоки
            blocks = self.split_into_blocks(text)

            encrypted_blocks = [idea.encrypt(block) for block in blocks]
            encrypted_text = self.join_blocks(encrypted_blocks)

            self.encrypted_entry.delete(0, tk.END)
            self.encrypted_entry.insert(0, encrypted_text.hex())
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректный ключ")

    def decrypt(self):
        encrypted_text = self.encrypted_entry.get()
        key = self.key_entry.get()
        if not encrypted_text or not key:
            messagebox.showerror("Ошибка", "Введите шифр и ключ")
            return
        try:
            key = int(key, 16)
            encrypted_data = bytes.fromhex(encrypted_text)
            idea = IDEA(key)

            # Разбиваем зашифрованный текст на блоки
            blocks = [int.from_bytes(encrypted_data[i:i+8], byteorder='big') for i in range(0, len(encrypted_data), 8)]

            decrypted_blocks = [idea.decrypt(block) for block in blocks]
            decrypted_text = self.join_blocks(decrypted_blocks).decode('utf-8', errors='ignore')

            self.decrypted_entry.delete(0, tk.END)
            self.decrypted_entry.insert(0, decrypted_text)
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректные данные")


if __name__ == "__main__":
    root = tk.Tk()
    app = IdeaApp(root)
    root.mainloop()
