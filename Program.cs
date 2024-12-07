using System.Net;
using System.Net.Sockets;
using System.Text;
using NAudio.Wave;

namespace Machamp
{
    internal static class Program
    {
        private static readonly HttpClient HttpClient = new();
        private static void Main()
        {
            const int port = 514;
            using var udpClient = new UdpClient(port);
            Console.WriteLine($"Listening for syslog events on UDP port {port}...");
            while (true)
            {
                try
                {
                    var remoteEndPoint = new IPEndPoint(IPAddress.Any, port);
                    var syslogMessage = Encoding.UTF8.GetString(udpClient.Receive(ref remoteEndPoint));
                    if (!syslogMessage.Contains("block") ||
                        !TryExtractDetails(syslogMessage, out var sourceIp, out var destPort, out var protocol) ||
                        !IsPublicIpAddress(sourceIp)) continue;
                    var location = GetLocationFromIpApiAsync(sourceIp).Result;
                    var description = GenerateAttackDescription(sourceIp, destPort, protocol, location);
                    Console.WriteLine(description);
                    PlayAlertSound();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        private static bool TryExtractDetails(string syslogMessage, out IPAddress? sourceIp, out int destPort, out string protocol)
        {
            sourceIp = null;
            destPort = 0;
            protocol = "unknown";
            try
            {
                var parts = syslogMessage.Split(',');
                foreach (var part in parts)
                {
                    if (IPAddress.TryParse(part.Trim(), out var ip) && ip.AddressFamily == AddressFamily.InterNetwork && sourceIp == null)
                    {
                        sourceIp = ip;
                    }
                    if (int.TryParse(part.Trim(), out var port) && port is > 0 and < 65536)
                    {
                        destPort = port;
                    }
                    if (part.Trim().Equals("tcp", StringComparison.OrdinalIgnoreCase) || part.Trim().Equals("udp", StringComparison.OrdinalIgnoreCase))
                    {
                        protocol = part.Trim();
                    }
                }
                return sourceIp != null && destPort > 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsPublicIpAddress(IPAddress? ipAddress)
        {
            if (ipAddress is { AddressFamily: AddressFamily.InterNetwork })
            {
                var bytes = ipAddress.GetAddressBytes();
                // Private IP ranges
                return bytes[0] != 10 && (bytes[0] != 172 || bytes[1] < 16 || bytes[1] > 31) && (bytes[0] != 192 || bytes[1] != 168) && (bytes[0] != 127) && (bytes[0] != 169 || bytes[1] != 254);
            }
            if (ipAddress is not { AddressFamily: AddressFamily.InterNetworkV6 }) return false;
            return ipAddress is { IsIPv6LinkLocal: false, IsIPv6SiteLocal: false } && !ipAddress.ToString().StartsWith("fd");
        }

        private static async Task<string> GetLocationFromIpApiAsync(IPAddress? ipAddress)
        {
            try
            {
                var url = $"http://ip-api.com/json/{ipAddress}";
                var response = await HttpClient.GetAsync(url);
                response.EnsureSuccessStatusCode();
                var responseContent = await response.Content.ReadAsStringAsync();
                if (!responseContent.Contains("\"country\":")) return "Unknown";
                var startIndex = responseContent.IndexOf("\"country\":", StringComparison.Ordinal) + 11;
                var endIndex = responseContent.IndexOf('"', startIndex);
                return responseContent.Substring(startIndex, endIndex - startIndex);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error performing IP-API lookup: {ex.Message}");
                return "Unknown";
            }
        }

        private static string GenerateAttackDescription(IPAddress? sourceIp, int destPort, string protocol, string location)
        {
            // Lookup for common port usages
            var portDescription = destPort switch
            {
                20 => "FTP Data Transfer",
                21 => "FTP Control",
                22 => "SSH (Secure Shell)",
                23 => "Telnet",
                25 => "SMTP (Email Sending)",
                53 => "DNS (Domain Name System)",
                80 => "HTTP (Web Traffic)",
                110 => "POP3 (Email Retrieval)",
                123 => "NTP (Network Time Protocol)",
                137 => "NetBIOS Name Service",
                138 => "NetBIOS Datagram Service",
                139 => "NetBIOS Session Service",
                143 => "IMAP (Email Retrieval)",
                161 => "SNMP (Simple Network Management Protocol)",
                162 => "SNMP Trap",
                179 => "BGP (Border Gateway Protocol)",
                194 => "IRC (Internet Relay Chat)",
                443 => "HTTPS (Secure Web Traffic)",
                445 => "SMB (Windows File Sharing)",
                465 => "SMTP (Secure Email Sending)",
                500 => "IKE (Internet Key Exchange)",
                514 => "Syslog",
                520 => "RIP (Routing Information Protocol)",
                554 => "RTSP (Streaming Protocol)",
                587 => "SMTP (Submission)",
                593 => "RPC over HTTP",
                631 => "IPP (Internet Printing Protocol)",
                636 => "LDAPS (Secure LDAP)",
                873 => "rsync",
                993 => "IMAPS (Secure IMAP)",
                995 => "POP3S (Secure POP3)",
                1025 => "Microsoft RPC",
                1080 => "SOCKS Proxy",
                1194 => "OpenVPN",
                1433 => "Microsoft SQL Server",
                1434 => "Microsoft SQL Monitor",
                1521 => "Oracle Database",
                1723 => "PPTP (VPN)",
                1900 => "SSDP (UPnP)",
                2049 => "NFS (Network File System)",
                3128 => "HTTP Proxy",
                3268 => "Global Catalog (LDAP)",
                3306 => "MySQL Database",
                3389 => "RDP (Remote Desktop Protocol)",
                3899 => "Radmin (Remote Admin)",
                3690 => "Subversion",
                5000 => "UPnP / Web Services",
                5432 => "PostgreSQL Database",
                5631 => "pcAnywhere",
                5900 => "VNC Remote Desktop",
                5985 => "Windows Remote Management (HTTP)",
                5986 => "Windows Remote Management (HTTPS)",
                6000 => "X11 Display Server",
                6379 => "Redis Database",
                8080 => "HTTP Proxy / Web Traffic",
                8443 => "HTTPS (Alternative Port)",
                9000 => "SonarQube",
                9090 => "HTTP Alternative",
                10000 => "Webmin",
                _ => "Unknown Service"
            };
            return
                $"ALERT: Blocked traffic detected from {sourceIp} ({location}) targeting port {destPort} ({portDescription}) over {protocol.ToUpper()}. ";
        }


        private static void PlayAlertSound()
        {
            try
            {
                using var audioFile = new AudioFileReader(@"C:\Windows\Media\tada.wav");
                using var outputDevice = new WaveOutEvent();
                outputDevice.Init(audioFile);
                outputDevice.Play();
                while (outputDevice.PlaybackState == PlaybackState.Playing)
                {
                    Thread.Sleep(50);
                }
            }
            catch (Exception)
            {
                // ignored
            }
        }
    }
}
