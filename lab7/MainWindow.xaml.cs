using System;
using System.Windows;

namespace lab7
{
    public partial class MainWindow : Window
    {
        private readonly EncryptionService encryptionService;
        private readonly DigitalSignatureService digitalSignatureService;

        public MainWindow()
        {
            InitializeComponent();
            encryptionService = new EncryptionService();
            digitalSignatureService = new DigitalSignatureService();
        }

        // Шифрование сообщения
        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string message = MessageTextBox.Text;
            byte[] encryptedMessage = encryptionService.EncryptMessage(message);
            ResultTextBox.Text = Convert.ToBase64String(encryptedMessage);
        }

        // Дешифрование сообщения
        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(ResultTextBox.Text))
            {
                ResultTextBox.Text = "Сначала зашифруйте сообщение.";
                return;
            }

            byte[] encryptedMessage = Convert.FromBase64String(ResultTextBox.Text);
            string decryptedMessage = encryptionService.DecryptMessage(encryptedMessage);
            ResultTextBox.Text = decryptedMessage;
        }

        // Добавление цифровой подписи
        private void SignButton_Click(object sender, RoutedEventArgs e)
        {
            string message = MessageTextBox.Text;
            byte[] messageSignature = digitalSignatureService.CreateSignature(message);
            ResultTextBox.Text = Convert.ToBase64String(messageSignature);
        }

        // Отправка сообщения (пока просто выводим сообщение о отправке)
        private void SendButton_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(ResultTextBox.Text))
            {
                ResultTextBox.Text = "Сообщение отправлено!";
            }
            else
            {
                ResultTextBox.Text = "Сначала зашифруйте сообщение.";
            }
        }
    }
}
