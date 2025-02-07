import tkinter as tk
from tkinter import messagebox
from IDEA import IDEA


class IDEAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IDEA Encryption/Decryption")
        self.root.geometry("500x400")

        # Поля для ввода
        self.input_text_label = tk.Label(root, text="Enter Plaintext (ASCII):")
        self.input_text_label.pack()
        self.input_text = tk.Entry(root, width=40)
        self.input_text.pack()

        self.encrypted_text_label = tk.Label(root, text="Encrypted (HEX):")
        self.encrypted_text_label.pack()
        self.encrypted_text = tk.Entry(root, width=40, state='readonly')
        self.encrypted_text.pack()

        self.decrypted_text_label = tk.Label(root, text="Decrypted (ASCII):")
        self.decrypted_text_label.pack()
        self.decrypted_text = tk.Entry(root, width=40, state='readonly')
        self.decrypted_text.pack()

        # Ключи для шифрования и дешифрования
        self.encryption_key_label = tk.Label(root, text="Enter Encryption Key (HEX):")
        self.encryption_key_label.pack()
        self.encryption_key = tk.Entry(root, width=40)
        self.encryption_key.insert(0, "0x6e3272357538782f413f4428472b4b62")  # Пример ключа по умолчанию
        self.encryption_key.pack()

        self.decryption_key_label = tk.Label(root, text="Enter Decryption Key (HEX):")
        self.decryption_key_label.pack()
        self.decryption_key = tk.Entry(root, width=40)
        self.decryption_key.insert(0, "0x6e3272357538782f413f4428472b4b62")  # Пример ключа по умолчанию
        self.decryption_key.pack()

        # Кнопки
        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=10)

    def encrypt(self):
        plain_text = self.input_text.get()
        if not plain_text:
            messagebox.showerror("Input Error", "Please enter plaintext")
            return

        try:
            # Преобразуем строку в число (ASCII)
            plain_text_ascii = int(plain_text.encode().hex(), 16)
            # plain_text_ascii = plain_text.encode('utf-8')

            encryption_key = self.encryption_key.get()
            if not encryption_key:
                messagebox.showerror("Key Error", "Please enter an encryption key")
                return

            key = int(encryption_key, 16)
            cipher = IDEA(key)
            encrypted = cipher.encrypt(plain_text_ascii)

            self.encrypted_text.config(state='normal')
            self.encrypted_text.delete(0, tk.END)
            self.encrypted_text.insert(0, hex(encrypted))
            self.encrypted_text.config(state='readonly')

        except ValueError:
            messagebox.showerror("Input Error", "Invalid key or text format")

    def decrypt(self):
        encrypted_text = self.encrypted_text.get()
        if not encrypted_text:
            messagebox.showerror("Input Error", "Please encrypt text first")
            return

        try:
            # Преобразуем HEX в число
            encrypted_text_hex = int(encrypted_text, 16)

            decryption_key = self.decryption_key.get()
            if not decryption_key:
                messagebox.showerror("Key Error", "Please enter a decryption key")
                return

            key = int(decryption_key, 16)
            cipher = IDEA(key)
            decrypted = cipher.decrypt(encrypted_text_hex)

            decrypted_text_ascii = bytes.fromhex(hex(decrypted)[2:]).decode()

            self.decrypted_text.config(state='normal')
            self.decrypted_text.delete(0, tk.END)
            self.decrypted_text.insert(0, decrypted_text_ascii)
            self.decrypted_text.config(state='readonly')

        except ValueError:
            messagebox.showerror("Input Error", "Invalid key or encrypted text format")


if __name__ == "__main__":
    root = tk.Tk()
    app = IDEAApp(root)
    root.mainloop()
