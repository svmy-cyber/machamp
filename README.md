Machamp: Syslog Monitoring with Alerts
========================================

Machamp is a lightweight application designed to monitor syslog messages for blocked network traffic, identify potential threats, and provide audio-visual alerts for suspicious activity. It also performs geographical lookups of IP addresses to enhance threat analysis.

Features
--------
- Monitors incoming syslog messages on UDP port 514.
- Detects blocked traffic and triggers an audio alert.
- Provides detailed descriptions of detected activity, including:
  - Source IP address.
  - Destination port and its typical usage.
  - Protocol type (TCP/UDP).
  - Geographical location of the source IP (via IP-API).
- Supports real-time logging for threat analysis.

Requirements
------------
- Operating System: Windows 10 or later.
- Dependencies:
  - .NET 6 Runtime (https://dotnet.microsoft.com/download/dotnet/6.0) or later.
  - Internet access for IP lookups (via IP-API).

Installation
------------
1. Clone this repository:
   git clone https://github.com/svmy-cyber/machamp.git

2. Build the project using the .NET SDK:
   dotnet build

3. Run the executable:
   dotnet run

Usage
-----
1. Start the application:
   dotnet run

2. Configure your network devices to send syslog messages to the machine running the app on UDP port 514.

3. Observe alerts in the console and listen for audio notifications for blocked traffic from external IPs.

Example Output
--------------
ALERT: Blocked traffic detected from 193.163.125.26 (Denmark) targeting port 22 (SSH) over TCP.

Customization
-------------
Change Alert Sound:
- Replace the file at C:\Windows\Media\tada.wav with your preferred .wav file.

Monitor Different Ports:
- Modify the listening port in the `Main` method:
  const int port = 514; // Change this to your desired port.

Known Issues
------------
- Firewall Restrictions: Ensure that UDP port 514 is open on the machine running the app.
- Accuracy of Geolocation: The IP-API service provides approximate geographical data.

License
-------
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments
---------------
- IP-API (https://ip-api.com/) for geolocation services.
- NAudio (https://github.com/naudio/NAudio) for audio playback.
- The open-source community for making this project possible.
