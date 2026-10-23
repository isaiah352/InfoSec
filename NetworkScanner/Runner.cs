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
        string targetIp = ""; // Replace with your target IP
        int startPort = 1;
        int endPort = 65535;

        Console.WriteLine($"Starting scan of {targetIp} from port {startPort} to {endPort}...");

        // Scan the range and process results
        await scanner.ScanRangeAsync(
            targetIp,
            startPort,
            endPort,
            protocol: System.Net.Sockets.ProtocolType.Tcp,
            timeout: 2000,
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
            });

        Console.WriteLine("Scan completed.");
    }
}