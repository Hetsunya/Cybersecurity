using System;
using System.Drawing;
using System.Windows.Forms;

namespace def7
{
    public partial class Form1 : Form
    {
        private RichTextBox txtChat; // Изменено на RichTextBox
        private TextBox txtIP;
        private TextBox txtPort;
        private Button btnStart;
        private TextBox txtMessage;
        private Button btnSend;
        private RadioButton rbServer;
        private RadioButton rbClient;

        private readonly NetworkManager networkManager;
        private readonly CryptoManager cryptoManager;
        private readonly ChatLogger chatLogger;

        private bool isServerRunning = false;

        public Form1()
        {
            InitializeComponent();
            SetupUI();
            cryptoManager = new CryptoManager();
            chatLogger = new ChatLogger(txtChat);
            networkManager = new NetworkManager(chatLogger, cryptoManager);
        }

        private void SetupUI()
        {
            this.Text = "7 лабораторная работа по дисциплине \"Защита информации\"";
            this.Width = 800;
            this.Height = 600;
            this.BackColor = Color.FromArgb(18, 18, 22);
            this.ForeColor = Color.FromArgb(220, 220, 220);
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;

            Panel settingsPanel = new Panel
            {
                Location = new Point(10, 10),
                Size = new Size(180, 580),
                BackColor = Color.FromArgb(25, 25, 30),
                BorderStyle = BorderStyle.FixedSingle
            };

            rbServer = new RadioButton
            {
                Text = "Сервер",
                ForeColor = Color.FromArgb(200, 200, 200),
                Location = new Point(10, 20),
                AutoSize = true,
                Font = new Font("Segoe UI", 10),
                Checked = true
            };
            rbClient = new RadioButton
            {
                Text = "Клиент",
                ForeColor = Color.FromArgb(200, 200, 200),
                Location = new Point(10, 50),
                AutoSize = true,
                Font = new Font("Segoe UI", 10)
            };

            Label lblIP = new() { Text = "IP:", ForeColor = Color.FromArgb(180, 180, 180), Location = new Point(10, 90), AutoSize = true, Font = new Font("Segoe UI", 9) };
            txtIP = new TextBox { Location = new Point(40, 87), Width = 130, BackColor = Color.FromArgb(40, 40, 45), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Text = "127.0.0.1", Font = new Font("Segoe UI", 10) };

            Label lblPort = new() { Text = "Порт:", ForeColor = Color.FromArgb(180, 180, 180), Location = new Point(10, 120), AutoSize = true, Font = new Font("Segoe UI", 9) };
            txtPort = new TextBox { Location = new Point(60, 117), Width = 110, BackColor = Color.FromArgb(40, 40, 45), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Text = "5000", Font = new Font("Segoe UI", 10) };

            btnStart = new Button { Text = "Запуск / Подключение", Location = new Point(10, 150), Width = 160, Height = 40, BackColor = Color.FromArgb(0, 120, 215), ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
            btnStart.FlatAppearance.BorderSize = 0;
            btnStart.Click += BtnStart_Click;
            btnStart.MouseEnter += (s, e) => btnStart.BackColor = Color.FromArgb(0, 150, 255);
            btnStart.MouseLeave += (s, e) => btnStart.BackColor = Color.FromArgb(0, 120, 215);

            txtChat = new RichTextBox
            {
                Location = new Point(200, 10),
                Width = 580,
                Height = 450,
                Multiline = true,
                ScrollBars = RichTextBoxScrollBars.Vertical,
                ReadOnly = true,
                BackColor = Color.FromArgb(25, 25, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 10)
            };

            txtMessage = new TextBox { Location = new Point(200, 470), Width = 480, Height = 80, Multiline = true, ScrollBars = ScrollBars.Vertical, BackColor = Color.FromArgb(40, 40, 45), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10) };
            btnSend = new Button { Text = "Отправить", Location = new Point(690, 470), Width = 90, Height = 80, BackColor = Color.FromArgb(0, 180, 80), ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
            btnSend.FlatAppearance.BorderSize = 0;
            btnSend.Click += BtnSend_Click;
            btnSend.MouseEnter += (s, e) => btnSend.BackColor = Color.FromArgb(0, 210, 100);
            btnSend.MouseLeave += (s, e) => btnSend.BackColor = Color.FromArgb(0, 180, 80);

            settingsPanel.Controls.Add(rbServer);
            settingsPanel.Controls.Add(rbClient);
            settingsPanel.Controls.Add(lblIP);
            settingsPanel.Controls.Add(txtIP);
            settingsPanel.Controls.Add(lblPort);
            settingsPanel.Controls.Add(txtPort);
            settingsPanel.Controls.Add(btnStart);

            this.Controls.Add(settingsPanel);
            this.Controls.Add(txtChat);
            this.Controls.Add(txtMessage);
            this.Controls.Add(btnSend);
        }

        private void BtnStart_Click(object sender, EventArgs e)
        {
            if (!isServerRunning && rbServer.Checked)
            {
                networkManager.StartServer(txtPort.Text);
                btnStart.Text = "Остановить сервер";
                isServerRunning = true;
            }
            else if (isServerRunning && rbServer.Checked)
            {
                networkManager.StopServer();
                btnStart.Text = "Запуск / Подключение";
                isServerRunning = false;
            }
            else if (!rbServer.Checked)
            {
                networkManager.StartClient(txtIP.Text, txtPort.Text);
            }
        }

        private void BtnSend_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtMessage.Text)) return;
            networkManager.SendMessage(txtMessage.Text);
            txtMessage.Clear();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            networkManager.Stop();
            base.OnFormClosing(e);
        }
    }
}