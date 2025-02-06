import tkinter as tk
from tkinter import messagebox
from cipher import encrypt, decrypt

def on_encrypt():
    text = entry_text.get()
    if not text:
        messagebox.showerror("Ошибка", "Введите текст")
        return
    encrypted = encrypt(text, 4)  # Фиксированное количество столбцов
    entry_result.delete(0, tk.END)
    entry_result.insert(0, encrypted)

def on_decrypt():
    text = entry_text.get()
    if not text:
        messagebox.showerror("Ошибка", "Введите зашифрованный текст")
        return
    try:
        decrypted = decrypt(text, 4)
        entry_result.delete(0, tk.END)
        entry_result.insert(0, decrypted)
    except Exception:
        messagebox.showerror("Ошибка", "Некорректные данные для расшифровки")

root = tk.Tk()
root.title("Шифрование текста")

# Поля ввода и кнопки
entry_text = tk.Entry(root, width=50)
entry_text.pack(pady=5)

btn_encrypt = tk.Button(root, text="Зашифровать", command=on_encrypt)
btn_encrypt.pack(pady=5)

btn_decrypt = tk.Button(root, text="Расшифровать", command=on_decrypt)
btn_decrypt.pack(pady=5)

entry_result = tk.Entry(root, width=50)
entry_result.pack(pady=5)

root.mainloop()
