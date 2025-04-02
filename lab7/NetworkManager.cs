using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace def7
{
    public class NetworkManager
    {
        private TcpListener listener;
        private TcpClient client;
        private NetworkStream netStream;
        private Thread listenThread;
        private Thread receiveThread;
        private bool stopThreads = false;

        private readonly ChatLogger chatLogger;
        private readonly CryptoManager cryptoManager;

        public NetworkManager(ChatLogger logger, CryptoManager crypto)
        {
            chatLogger = logger;
            cryptoManager = crypto;
        }

        public void StartServer(string portText)
        {
            stopThreads = false;
            int port = int.Parse(portText);
            listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            chatLogger.Log("Сервер запущен. Ожидаем подключения...", ChatLogger.LogType.Info);

            listenThread = new Thread(() =>
            {
                try
                {
                    client = listener.AcceptTcpClient();
                    netStream = client.GetStream();
                    chatLogger.LogThreadSafe("Клиент подключился", ChatLogger.LogType.Info);

                    chatLogger.LogThreadSafe("Ожидаем ключ от клиента...", ChatLogger.LogType.Info);
                    cryptoManager.ReceiveOtherSidePublicKey(netStream, chatLogger);
                    chatLogger.LogThreadSafe("Отправляем наш ключ клиенту...", ChatLogger.LogType.Info);
                    cryptoManager.SendOurPublicKey(netStream, chatLogger);

                    StartReceiveLoop();
                }
                catch (Exception ex)
                {
                    if (!stopThreads) chatLogger.LogThreadSafe("Ошибка на сервере: " + ex.Message, ChatLogger.LogType.Error);
                }
            })
            { IsBackground = true };
            listenThread.Start();
        }

        public void StartClient(string ip, string portText)
        {
            stopThreads = false;
            int port = int.Parse(portText);

            try
            {
                client = new TcpClient();
                chatLogger.Log("Попытка подключения к серверу...", ChatLogger.LogType.Info);
                client.Connect(IPAddress.Parse(ip), port);
                netStream = client.GetStream();
                chatLogger.Log("Клиент подключился к серверу.", ChatLogger.LogType.Info);

                chatLogger.Log("Отправляем наш ключ серверу...", ChatLogger.LogType.Info);
                cryptoManager.SendOurPublicKey(netStream, chatLogger);
                chatLogger.Log("Ожидаем ключ от сервера...", ChatLogger.LogType.Info);
                cryptoManager.ReceiveOtherSidePublicKey(netStream, chatLogger);

                StartReceiveLoop();
            }
            catch (Exception ex)
            {
                chatLogger.Log("Ошибка при подключении клиента: " + ex.Message, ChatLogger.LogType.Error);
            }
        }

        public void StopServer()
        {
            stopThreads = true;
            try
            {
                listener?.Stop();
                client?.Close();
                netStream?.Close();
                listenThread?.Join(1000);
                receiveThread?.Join(1000);
                chatLogger.LogThreadSafe("Сервер остановлен.", ChatLogger.LogType.Info);
            }
            catch (Exception ex)
            {
                chatLogger.LogThreadSafe("Ошибка при остановке сервера: " + ex.Message, ChatLogger.LogType.Error);
            }
        }

        public void Stop()
        {
            stopThreads = true;
            listener?.Stop();
            client?.Close();
            netStream?.Close();
        }

        public void SendMessage(string message)
        {
            if (netStream == null || !netStream.CanWrite)
            {
                chatLogger.Log("Нет активного соединения.", ChatLogger.LogType.Error);
                return;
            }
            if (cryptoManager.OtherSideRSA == null)
            {
                chatLogger.Log("Нет публичного ключа собеседника.", ChatLogger.LogType.Error);
                return;
            }
            cryptoManager.SendEncryptedMessage(netStream, message, chatLogger);
        }

        private void StartReceiveLoop()
        {
            receiveThread = new Thread(() => cryptoManager.ReceiveLoop(netStream, chatLogger, ref stopThreads))
            { IsBackground = true };
            receiveThread.Start();
        }
    }
}