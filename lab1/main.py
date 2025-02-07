import tkinter as tk
from tkinter import messagebox
from cipher import *

def on_encrypt():
    text = entry_text.get()
    try:
        shift = int(entry_shift.get())  # Чтение сдвига
        if not text:
            messagebox.showerror("Ошибка", "Введите текст для шифрования")
            return
        encrypted = encrypt(text, shift)
        entry_result.delete(0, tk.END)
        entry_result.insert(0, encrypted)
    except ValueError:
        messagebox.showerror("Ошибка", "Введите корректное число для сдвига")

def on_decrypt():
    text = entry_text.get()
    try:
        shift = int(entry_shift.get())  # Чтение сдвига
        if not text:
            messagebox.showerror("Ошибка", "Введите зашифрованный текст")
            return
        decrypted = decrypt(text, shift)
        entry_result.delete(0, tk.END)
        entry_result.insert(0, decrypted)
    except ValueError:
        messagebox.showerror("Ошибка", "Введите корректное число для сдвига")

root = tk.Tk()
root.title("Шифрование Цезаря")

# Поля ввода и кнопки
entry_text = tk.Entry(root, width=50)
entry_text.pack(pady=5)

entry_shift = tk.Entry(root, width=10)
entry_shift.pack(pady=5)
entry_shift.insert(0, "3")

btn_encrypt = tk.Button(root, text="Зашифровать", command=on_encrypt)
btn_encrypt.pack(pady=5)

btn_decrypt = tk.Button(root, text="Расшифровать", command=on_decrypt)
btn_decrypt.pack(pady=5)

entry_result = tk.Entry(root, width=50)
entry_result.pack(pady=5)

root.mainloop()
