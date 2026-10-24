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
        Console.WriteLine("Starting full IPv4 scan...");

        // Scan all IPs. This will run concurrently in batches defined by the scanner's internal concurrency settings.
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

        Console.WriteLine("Scan completed.");
    }
}