using System.Net;
using System.Net.Sockets;

namespace NetworkScanner;

public class ScannerService : IDisposable
{
    private const int DefaultTimeout = 3000;
    private const int MaxPort = 65535;
    private readonly int _maxConcurrentScans;
    private bool _disposed;

    public class ScanResult
    {
        public bool Success { get; set; }
        public string? Host { get; set; }
        public int Port { get; set; }
        public ProtocolType Protocol { get; set; }
        public string? ServiceName { get; set; }
        public string? Version { get; set; }
        public string? Banner { get; set; }
        public string? Os { get; set; }
        public TimeSpan ResponseTime { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public ScannerService(int maxConcurrentScans = 100)
    {
        _maxConcurrentScans = maxConcurrentScans;
    }

    public async Task<ScanResult> ScanPortAsync(string host, int port, ProtocolType protocol = ProtocolType.Tcp, int timeout = DefaultTimeout)
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentException("Host cannot be null or empty", nameof(host));

        if (port < 1 || port > MaxPort)
            throw new ArgumentOutOfRangeException(nameof(port), $"Port must be between 1 and {MaxPort}");

        var result = new ScanResult
        {
            Host = host,
            Port = port,
            Protocol = protocol
        };

        try
        {
            var endpoint = new IPEndPoint(IPAddress.Parse(host), port);
            using var socket = CreateSocket(protocol);
            socket.ReceiveTimeout = timeout;
            socket.SendTimeout = timeout;

            var connectTask = socket.ConnectAsync(endpoint);
            var timeoutTask = Task.Delay(timeout);

            var completedTask = await Task.WhenAny(connectTask, timeoutTask);

            if (completedTask == timeoutTask)
            {
                result.Success = false;
                result.ErrorMessage = "Connection timed out";
                return result;
            }

            if (!socket.Connected)
            {
                result.Success = false;
                result.ErrorMessage = "Connection failed";
                return result;
            }

            result.Success = true;
            result.ServiceName = GetServiceName(port, protocol);
            result.ResponseTime = TimeSpan.FromMilliseconds(timeout);

            // Only attempt banner grabbing for TCP
            if (protocol == ProtocolType.Tcp)
            {
                result.Banner = await TryGetBannerAsync(socket, timeout);
                result.Version = await TryGetVersionAsync(socket, timeout);
                result.Os = await TryDetectOsAsync(socket, timeout);
            }
        }
        catch (SocketException ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.SocketErrorCode.ToString();
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    public async Task ScanRangeAsync(string host, int startPort, int endPort, Action<ScanResult> resultHandler, ProtocolType protocol = ProtocolType.Tcp, int timeout = DefaultTimeout)
    {
        if (startPort < 1 || startPort > MaxPort)
            throw new ArgumentOutOfRangeException(nameof(startPort), $"Start port must be between 1 and {MaxPort}");

        if (endPort < 1 || endPort > MaxPort)
            throw new ArgumentOutOfRangeException(nameof(endPort), $"End port must be between 1 and {MaxPort}");

        if (startPort > endPort)
            throw new ArgumentException("Start port must be less than or equal to end port");

        var semaphore = new SemaphoreSlim(_maxConcurrentScans);
        var tasks = new Task[(endPort - startPort) + 1];

        for (int port = startPort; port <= endPort; port++)
        {
            int currentPort = port;
            tasks[port - startPort] = Task.Run(async () =>
            {
                await semaphore.WaitAsync();
                try
                {
                    var result = await ScanPortAsync(host, currentPort, protocol, timeout);
                    resultHandler.Invoke(result);
                }
                finally
                {
                    semaphore.Release();
                }
            });
        }

        await Task.WhenAll(tasks);
    }

    private Socket CreateSocket(ProtocolType protocol)
    {
        return new Socket(AddressFamily.InterNetwork,
                         protocol == ProtocolType.Tcp ? SocketType.Stream : SocketType.Dgram,
                         protocol == ProtocolType.Tcp ? ProtocolType.Tcp : ProtocolType.Udp);
    }

    private string GetServiceName(int port, ProtocolType protocol)
    {
        // Using IANA assigned port numbers
        switch (protocol)
        {
            case ProtocolType.Tcp:
                switch (port)
                {
                    case 20: return "FTP (Data)";
                    case 21: return "FTP (Control)";
                    case 22: return "SSH";
                    case 23: return "Telnet";
                    case 25: return "SMTP";
                    case 53: return "DNS";
                    case 80: return "HTTP";
                    case 110: return "POP3";
                    case 119: return "NNTP";
                    case 143: return "IMAP";
                    case 161: return "SNMP";
                    case 162: return "SNMP Trap";
                    case 194: return "IRC";
                    case 443: return "HTTPS";
                    case 465: return "SMTPS";
                    case 587: return "Submission";
                    case 993: return "IMAPS";
                    case 995: return "POP3S";
                    case 3389: return "RDP";
                    default: return "Unknown";
                }
            case ProtocolType.Udp:
                switch (port)
                {
                    case 53: return "DNS";
                    case 67: return "DHCP (Server)";
                    case 68: return "DHCP (Client)";
                    case 69: return "TFTP";
                    case 123: return "NTP";
                    case 161: return "SNMP";
                    case 162: return "SNMP Trap";
                    case 500: return "IKE";
                    case 514: return "Syslog";
                    case 520: return "RIP";
                    default: return "Unknown";
                }
            default:
                return "Unknown";
        }
    }

    private static async Task<string> TryGetBannerAsync(Socket socket, int timeout)
    {
        try
        {
            var buffer = new byte[1024];
            var receiveTask = socket.ReceiveAsync(buffer, SocketFlags.None);
            var timeoutTask = Task.Delay(timeout);

            var completedTask = await Task.WhenAny(receiveTask, timeoutTask);

            if (completedTask == timeoutTask)
                return null;

            var bytesReceived = receiveTask.Result;
            return System.Text.Encoding.ASCII.GetString(buffer, 0, bytesReceived);
        }
        catch
        {
            return null;
        }
    }

    private async Task<string> TryGetVersionAsync(Socket socket, int timeout)
    {
        try
        {
            // Simple version detection by sending a minimal request
            var request = System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: \r\n\r\n");
            await socket.SendAsync(new ArraySegment<byte>(request), SocketFlags.None);

            var buffer = new byte[1024];
            var receiveTask = socket.ReceiveAsync(buffer, SocketFlags.None);
            var timeoutTask = Task.Delay(timeout);

            var completedTask = await Task.WhenAny(receiveTask, timeoutTask);

            if (completedTask == timeoutTask)
                return null;

            var bytesReceived = receiveTask.Result;
            var response = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesReceived);

            // Simple version detection from response
            if (response.Contains("HTTP/"))
            {
                var versionLine = response.Split('\n')[0];
                return versionLine.Split(' ')[1];
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private async Task<string> TryDetectOsAsync(Socket socket, int timeout)
    {
        try
        {
            // Simple OS detection based on TCP/IP stack behavior
            var buffer = new byte[1];
            await socket.SendAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

            var receiveTask = socket.ReceiveAsync(buffer, SocketFlags.None);
            var timeoutTask = Task.Delay(timeout);

            var completedTask = await Task.WhenAny(receiveTask, timeoutTask);

            if (completedTask == timeoutTask)
                return "Unknown (timeout)";

            // This is a very basic detection - real OS detection would be more complex
            return "Unknown (basic detection)";
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            // Clean up any resources
        }
        _disposed = true;
    }
}