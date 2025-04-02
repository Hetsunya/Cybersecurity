using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace def7
{
    public partial class Form1 : Form
    {
        private TextBox txtIP;
        private TextBox txtPort;
        private Button btnStart;
        private TextBox txtChat;
        private TextBox txtMessage;
        private Button btnSend;

        private TcpListener listener;
        private TcpClient client;
        private NetworkStream netStream;
        private Thread listenThread;
        private Thread receiveThread;

        private readonly RSA ourRSA;
        private RSA otherSideRSA;

        private bool stopThreads = false;

        private bool isServerRunning = false;


        public Form1()
        {
            InitializeComponent();
            SetupUI();
            ourRSA = RSA.Create();
        }

        private void SetupUI()
        {
            this.Text = "7 лабораторная работа по дисциплине \"Защита информации\"";
            this.Width = 800;
            this.Height = 600;
            this.BackColor = Color.FromArgb(30, 30, 30);
            this.ForeColor = Color.White;

            rbServer = new RadioButton
            {
                Text = "Сервер",
                ForeColor = Color.White,
                Location = new Point(20, 20),
                AutoSize = true
            };

            rbClient = new RadioButton
            {
                Text = "Клиент",
                ForeColor = Color.White,
                Location = new Point(20, 40),
                AutoSize = true
            };
            rbServer.Checked = true;

            Label lblIP = new()
            {
                Text = "IP:",
                ForeColor = Color.White,
                Location = new Point(15, 70),
                AutoSize = true
            };

            txtIP = new TextBox
            {
                Location = new Point(40, 67),
                Width = 120,
                BackColor = Color.FromArgb(60, 60, 60),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Text = "127.0.0.1"
            };

            Label lblPort = new()
            {
                Text = "Порт:",
                ForeColor = Color.White,
                Location = new Point(15, 100),
                AutoSize = true
            };

            txtPort = new TextBox
            {
                Location = new Point(60, 98),
                Width = 100,
                BackColor = Color.FromArgb(60, 60, 60),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Text = "5000"
            };

            btnStart = new Button
            {
                Text = "Запуск / Подключение",
                Location = new Point(15, 130),
                Width = 180,
                Height = 30,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnStart.FlatAppearance.BorderSize = 0;
            btnStart.Click += BtnStart_Click;

            txtChat = new TextBox()
            {
                Left = 210,
                Top = 10,
                Width = 560,
                Height = 450,
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true
            };

            txtMessage = new TextBox() 
            { 
                Left = 210, 
                Top = 470,
                Width = 420, 
                Height = 60, 
                Multiline = true, 
                ScrollBars = ScrollBars.Vertical 
            };
            
            btnSend = new Button() 
            { 
                Text = "Отправить сообщение", 
                Left = 660, 
                Top = 470, 
                Width = 100, 
                Height = 60,
                BackColor = Color.Green,
                ForeColor = Color.White,
            };
            btnSend.Click += BtnSend_Click;

            this.Controls.Add(rbServer);
            this.Controls.Add(rbClient);
            this.Controls.Add(lblIP);
            this.Controls.Add(txtIP);
            this.Controls.Add(lblPort);
            this.Controls.Add(txtPort);
            this.Controls.Add(btnStart);
            this.Controls.Add(txtChat);
            this.Controls.Add(txtMessage);
            this.Controls.Add(btnSend);


        }

        private void BtnStart_Click(object sender, EventArgs e)
        {
            if (!isServerRunning && rbServer.Checked)
            {
                StartServer();
                btnStart.Text = "Остановить сервер";
                isServerRunning = true;
            }
            else if (isServerRunning && rbServer.Checked)
            {
                StopServer();
                btnStart.Text = "Запуск / Подключение";
                isServerRunning = false;
            }
            else if (!rbServer.Checked)
            {
                StartClient();
            }
        }

        private void StopServer()
        {
            stopThreads = true;
            try
            {
                listener?.Stop();
                client?.Close();
                netStream?.Close();
                listenThread?.Join(1000); // Ждём завершения потока
                receiveThread?.Join(1000);
                AppendChatThreadSafe("Сервер остановлен.");
            }
            catch (Exception ex)
            {
                AppendChatThreadSafe("Ошибка при остановке сервера: " + ex.Message);
            }
        }

        private void BtnSend_Click(object sender, EventArgs e)
        {
            if (netStream == null || !netStream.CanWrite || string.IsNullOrWhiteSpace(txtMessage.Text)) return;
            if (otherSideRSA == null)
            {
                AppendChat("Нет публичного RSA-ключа собеседника.");
                return;
            }

            string message = txtMessage.Text.Trim();
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            // Подпись сообщения
            byte[] signature = ourRSA.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            byte[] sigLenBytes = BitConverter.GetBytes(signature.Length);

            // Шифрование сообщения RSA
            byte[] encryptedMessage = otherSideRSA.Encrypt(messageBytes, RSAEncryptionPadding.Pkcs1);

            AppendChat($"Вы: {message} (Подпись: {Convert.ToBase64String(signature)}, Зашифровано: {Convert.ToBase64String(encryptedMessage)})");

            using (MemoryStream ms = new())
            {
                ms.Write(sigLenBytes, 0, sigLenBytes.Length);
                ms.Write(signature, 0, signature.Length);
                ms.Write(encryptedMessage, 0, encryptedMessage.Length);

                byte[] combined = ms.ToArray();
                byte[] lengthBytes = BitConverter.GetBytes(combined.Length);
                netStream.Write(lengthBytes, 0, lengthBytes.Length);
                netStream.Write(combined, 0, combined.Length);
            }

            AppendChat($"Вы: {message} (Зашифровано: {Convert.ToBase64String(encryptedMessage)})");
            txtMessage.Clear();
        }
        private void StartServer()
        {
            stopThreads = false;
            int port = int.Parse(txtPort.Text);
            listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            AppendChat("Сервер запущен. Ожидаем подключения...");

            listenThread = new Thread(() =>
            {
                try
                {
                    client = listener.AcceptTcpClient();
                    netStream = client.GetStream();
                    AppendChatThreadSafe("Клиент подключился");

                    ReceiveOtherSidePublicKey();
                    SendOurPublicKey();

                    receiveThread = new Thread(ReceiveLoop);
                    receiveThread.Start();
                }
                catch (Exception ex)
                {
                    if (!stopThreads) AppendChatThreadSafe("Ошибка на сервере: " + ex.Message);
                }
            })
            {
                IsBackground = true
            };
            listenThread.Start();
        }

        private void StartClient()
        {
            stopThreads = false;
            string ip = txtIP.Text.Trim();
            int port = int.Parse(txtPort.Text);

            try
            {
                client = new TcpClient();
                client.Connect(IPAddress.Parse(ip), port);
                netStream = client.GetStream();
                AppendChat("Клиент подлючился к серверу.");

                SendOurPublicKey();
                ReceiveOtherSidePublicKey();



                receiveThread = new Thread(ReceiveLoop);
                receiveThread.Start();
            }
            catch (Exception ex)
            {
                AppendChat("Ошибка при подключении клиента: " + ex.Message);
            }
        }

        private void ReceiveOtherSidePublicKey()
        {
            try
            {
                byte[] lengthBytes = new byte[4];
                ReadExact(lengthBytes, 4);
                int keyLength = BitConverter.ToInt32(lengthBytes, 0);

                byte[] keyBytes = new byte[keyLength];
                ReadExact(keyBytes, keyLength);

                string publicKeyXml = Encoding.UTF8.GetString(keyBytes);
                RSA rsa = RSA.Create();
                rsa.FromXmlString(publicKeyXml);
                otherSideRSA = rsa;

                AppendChatThreadSafe($"Получен публичный ключ собеседника: {publicKeyXml}");
            }
            catch (Exception ex)
            {
                AppendChatThreadSafe("Ошибка получения публичного ключа: " + ex.Message);
            }
        }

        private void SendOurPublicKey()
        {
            try
            {
                string xmlPublicKey = ourRSA.ToXmlString(false);
                byte[] keyBytes = Encoding.UTF8.GetBytes(xmlPublicKey);
                byte[] lengthBytes = BitConverter.GetBytes(keyBytes.Length);
                netStream.Write(lengthBytes, 0, lengthBytes.Length);
                netStream.Write(keyBytes, 0, keyBytes.Length);
                AppendChatThreadSafe($"Наш публичный ключ отправлен: {xmlPublicKey}");
            }
            catch (Exception ex)
            {
                AppendChatThreadSafe("Ошибка отправки публичного ключа: " + ex.Message);
            }
        }


        private void ReceiveLoop()
        {
            while (!stopThreads)
            {
                try
                {
                    byte[] lengthBytes = new byte[4];
                    int readCount = netStream.Read(lengthBytes, 0, 4);
                    if (readCount == 0) break;
                    int dataLength = BitConverter.ToInt32(lengthBytes, 0);

                    byte[] data = new byte[dataLength];
                    ReadExact(data, dataLength);

                    int sigLen = BitConverter.ToInt32(data, 0);
                    byte[] signBytes = new byte[sigLen];
                    Buffer.BlockCopy(data, 4, signBytes, 0, sigLen);

                    int encMsgOffset = 4 + sigLen;
                    int encMsgLen = data.Length - encMsgOffset;
                    byte[] encryptedMessage = new byte[encMsgLen];
                    Buffer.BlockCopy(data, encMsgOffset, encryptedMessage, 0, encMsgLen);

                    byte[] decryptedMessage = ourRSA.Decrypt(encryptedMessage, RSAEncryptionPadding.Pkcs1);
                    string message = Encoding.UTF8.GetString(decryptedMessage);

                    bool valid = otherSideRSA.VerifyData(decryptedMessage, signBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    if (valid)
                        AppendChatThreadSafe($"Собеседник: {message} (Зашифровано: {Convert.ToBase64String(encryptedMessage)})");
                    else
                        AppendChatThreadSafe("Сообщение с НЕВЕРНОЙ подписью!");
                }
                catch (Exception ex)
                {
                    if (!stopThreads) AppendChatThreadSafe("Ошибка приёма: " + ex.Message);
                    break;
                }
            }
        }


        private void ReadExact(byte[] buffer, int size)
        {
            int offset = 0;
            while (offset < size)
            {
                int r = netStream.Read(buffer, offset, size - offset);
                if (r == 0) throw new Exception("ОШИБКА.");
                offset += r;
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            stopThreads = true;
            try
            {
                listener?.Stop();
                client?.Close();
            }
            catch { }
            base.OnFormClosing(e);
        }

        private void AppendChat(string text)
        {
            txtChat.AppendText(text + Environment.NewLine);
        }

        private void AppendChatThreadSafe(string text)
        {
            if (txtChat.InvokeRequired) txtChat.Invoke(new Action<string>(AppendChat), text);
            else AppendChat(text);
        }

        private void Form1_Load(object sender, EventArgs e) { }
    }
}
