using System;
using System.Security.Cryptography;
using System.Text;

namespace lab7
{
    public class EncryptionService
    {
        private readonly RSACryptoServiceProvider rsa;

        public EncryptionService()
        {
            rsa = new RSACryptoServiceProvider();
        }

        // Шифрование
        public byte[] EncryptMessage(string data)
        {
            return rsa.Encrypt(Encoding.UTF8.GetBytes(data), false); // false для публичного ключа
        }

        // Дешифрование
        public string DecryptMessage(byte[] encryptedData)
        {
            byte[] decryptedData = rsa.Decrypt(encryptedData, false);
            return Encoding.UTF8.GetString(decryptedData);
        }

        // Получить публичный и приватный ключ
        public string GetPublicKey() => rsa.ToXmlString(false);
        public string GetPrivateKey() => rsa.ToXmlString(true);
    }
}
