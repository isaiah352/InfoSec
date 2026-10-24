using System;
using System.Net;
using System.Threading.Tasks;

namespace NetworkScanner;

class Runner
{
    static async Task Main(string[] args)
    {
        // Create a scanner with 50 concurrent scans
        using var scanner = new ScannerService(maxConcurrentScans: 50);

        // Define the target IP address and port range
        const int startPort = 1;
        const int endPort = 65535;

        if (args.Length > 0 && System.Net.IPAddress.TryParse(args[0], out var parsedIp) && parsedIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            // User provided a valid IPv4 address – perform a port scan only on that host
            string host = args[0];
            Console.WriteLine($"Scanning single IP address: {host}");
            await scanner.ScanRangeAsync(host, startPort, endPort, resultHandler: result =>
            {
                if (result.Success)
                {
                    Console.WriteLine($"[OPEN] {result.Host}:{result.Port} - {result.ServiceName}");
                    if (!string.IsNullOrEmpty(result.Banner))
                    {
                        Console.WriteLine($"  Banner: {result.Banner}");
                    }
                    if (!string.IsNullOrEmpty(result.Version))
                    {
                        Console.WriteLine($"  Version: {result.Version}");
                    }
                }
                else
                {
                    // Uncomment this line to see closed ports in the console output
                    //Console.WriteLine($"[CLOSED] {result.Host}:{result.Port}");
                }
            }, protocol: System.Net.Sockets.ProtocolType.Tcp, timeout: 2000);
        }
        else
        {
            // No IP provided – fall back to full IPv4 scan
            Console.WriteLine("Starting full IPv4 scan...");
            await scanner.ScanAllIpsAsync(
                resultHandler: result =>
                {
                    if (result.Success)
                    {
                        Console.WriteLine($"[OPEN] {result.Host}:{result.Port} - {result.ServiceName}");
                        if (!string.IsNullOrEmpty(result.Banner))
                        {
                            Console.WriteLine($"  Banner: {result.Banner}");
                        }
                        if (!string.IsNullOrEmpty(result.Version))
                        {
                            Console.WriteLine($"  Version: {result.Version}");
                        }
                    }
                    else
                    {
                        // Uncomment this line to see closed ports in the console output
                        //Console.WriteLine($"[CLOSED] {result.Host}:{result.Port}");
                    }
                },
                protocol: System.Net.Sockets.ProtocolType.Tcp,
                timeout: 2000,
                maxConcurrentIps: 5);
        }

        Console.WriteLine("Scan completed.");
    }
}