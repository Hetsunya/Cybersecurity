using System;
using System.Drawing;
using System.Windows.Forms;

namespace def7
{
    public class ChatLogger
    {
        private readonly RichTextBox txtChat;

        public enum LogType
        {
            Info,       // Системные сообщения (сервер запущен, клиент подключился)
            Message,    // Сообщения от пользователей
            Key,        // Ключи RSA
            Error       // Ошибки
        }

        public ChatLogger(RichTextBox chatBox)
        {
            txtChat = chatBox;
        }

        public void Log(string text, LogType type = LogType.Info)
        {
            Color color = GetColorForType(type);
            AppendText(text, color);
        }

        public void LogThreadSafe(string text, LogType type = LogType.Info)
        {
            if (txtChat.InvokeRequired)
                txtChat.Invoke(new Action<string, LogType>(Log), text, type);
            else
                Log(text, type);
        }

        private void AppendText(string text, Color color)
        {
            txtChat.SelectionStart = txtChat.TextLength;
            txtChat.SelectionLength = 0;
            txtChat.SelectionColor = color;
            txtChat.AppendText(text + Environment.NewLine);
            txtChat.SelectionColor = txtChat.ForeColor; // Сбрасываем цвет
            txtChat.ScrollToCaret(); // Прокручиваем вниз
        }

        private Color GetColorForType(LogType type)
        {
            return type switch
            {
                LogType.Info => Color.FromArgb(150, 150, 255),    // Светло-синий для системных сообщений
                LogType.Message => Color.FromArgb(0, 255, 150),   // Зелёный для сообщений
                LogType.Key => Color.FromArgb(255, 200, 100),     // Оранжевый для ключей
                LogType.Error => Color.FromArgb(255, 100, 100),   // Красный для ошибок
                _ => Color.FromArgb(220, 220, 220)                // Белый по умолчанию
            };
        }
    }
}