using System.Security.Cryptography;
using System.Text;

namespace lab7
{
    public class DigitalSignatureService
    {
        private readonly RSACryptoServiceProvider rsa;

        public DigitalSignatureService()
        {
            rsa = new RSACryptoServiceProvider();
        }

        // Создание цифровой подписи
        public byte[] CreateSignature(string message)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(message));
                return rsa.SignHash(hash, CryptoConfig.MapNameToOID("SHA256"));
            }
        }

        // Проверка цифровой подписи
        public bool VerifySignature(string message, byte[] signature)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(message));
                return rsa.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA256"), signature);
            }
        }
    }
}
