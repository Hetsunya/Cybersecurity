using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace def7
{
    public class CryptoManager
    {
        private readonly RSA ourRSA;
        public RSA OtherSideRSA { get; private set; }

        public CryptoManager()
        {
            ourRSA = RSA.Create();
        }

        public void SendOurPublicKey(NetworkStream stream, ChatLogger logger)
        {
            try
            {
                string xmlPublicKey = ourRSA.ToXmlString(false);
                byte[] keyBytes = Encoding.UTF8.GetBytes(xmlPublicKey);
                byte[] lengthBytes = BitConverter.GetBytes(keyBytes.Length);
                stream.Write(lengthBytes, 0, lengthBytes.Length);
                stream.Write(keyBytes, 0, keyBytes.Length);
                logger.LogThreadSafe($"Наш публичный ключ отправлен: {xmlPublicKey}", ChatLogger.LogType.Key);
            }
            catch (Exception ex)
            {
                logger.LogThreadSafe("Ошибка отправки публичного ключа: " + ex.Message, ChatLogger.LogType.Error);
            }
        }

        public void ReceiveOtherSidePublicKey(NetworkStream stream, ChatLogger logger)
        {
            try
            {
                byte[] lengthBytes = new byte[4];
                ReadExact(stream, lengthBytes, 4);
                int keyLength = BitConverter.ToInt32(lengthBytes, 0);

                byte[] keyBytes = new byte[keyLength];
                ReadExact(stream, keyBytes, keyLength);

                string publicKeyXml = Encoding.UTF8.GetString(keyBytes);
                RSA rsa = RSA.Create();
                rsa.FromXmlString(publicKeyXml);
                OtherSideRSA = rsa;

                logger.LogThreadSafe($"Получен публичный ключ собеседника: {publicKeyXml}", ChatLogger.LogType.Key);
            }
            catch (Exception ex)
            {
                logger.LogThreadSafe("Ошибка получения публичного ключа: " + ex.Message, ChatLogger.LogType.Error);
            }
        }

        public void SendEncryptedMessage(NetworkStream stream, string message, ChatLogger logger)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] signature = ourRSA.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            byte[] sigLenBytes = BitConverter.GetBytes(signature.Length);
            byte[] encryptedMessage = OtherSideRSA.Encrypt(messageBytes, RSAEncryptionPadding.Pkcs1);

            logger.Log($"Вы: {message} (Подпись: {Convert.ToBase64String(signature)}, Зашифровано: {Convert.ToBase64String(encryptedMessage)})", ChatLogger.LogType.Message);

            using (MemoryStream ms = new())
            {
                ms.Write(sigLenBytes, 0, sigLenBytes.Length);
                ms.Write(signature, 0, signature.Length);
                ms.Write(encryptedMessage, 0, encryptedMessage.Length);

                byte[] combined = ms.ToArray();
                byte[] lengthBytes = BitConverter.GetBytes(combined.Length);
                stream.Write(lengthBytes, 0, lengthBytes.Length);
                stream.Write(combined, 0, combined.Length);
            }
        }

        public void ReceiveLoop(NetworkStream stream, ChatLogger logger, ref bool stopThreads)
        {
            while (!stopThreads)
            {
                try
                {
                    byte[] lengthBytes = new byte[4];
                    int readCount = stream.Read(lengthBytes, 0, 4);
                    if (readCount == 0) break;
                    int dataLength = BitConverter.ToInt32(lengthBytes, 0);

                    byte[] data = new byte[dataLength];
                    ReadExact(stream, data, dataLength);

                    int sigLen = BitConverter.ToInt32(data, 0);
                    byte[] signBytes = new byte[sigLen];
                    Buffer.BlockCopy(data, 4, signBytes, 0, sigLen);

                    int encMsgOffset = 4 + sigLen;
                    int encMsgLen = data.Length - encMsgOffset;
                    byte[] encryptedMessage = new byte[encMsgLen];
                    Buffer.BlockCopy(data, encMsgOffset, encryptedMessage, 0, encMsgLen);

                    byte[] decryptedMessage = ourRSA.Decrypt(encryptedMessage, RSAEncryptionPadding.Pkcs1);
                    string message = Encoding.UTF8.GetString(decryptedMessage);

                    bool valid = OtherSideRSA.VerifyData(decryptedMessage, signBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    if (valid)
                        logger.LogThreadSafe($"Собеседник: {message} (Зашифровано: {Convert.ToBase64String(encryptedMessage)})", ChatLogger.LogType.Message);
                    else
                        logger.LogThreadSafe("Сообщение с НЕВЕРНОЙ подписью!", ChatLogger.LogType.Error);
                }
                catch (Exception ex)
                {
                    if (!stopThreads) logger.LogThreadSafe("Ошибка приёма: " + ex.Message, ChatLogger.LogType.Error);
                    break;
                }
            }
        }

        private void ReadExact(NetworkStream stream, byte[] buffer, int size)
        {
            int offset = 0;
            while (offset < size)
            {
                int r = stream.Read(buffer, offset, size - offset);
                if (r == 0) throw new Exception("Соединение прервано.");
                offset += r;
            }
        }
    }
}