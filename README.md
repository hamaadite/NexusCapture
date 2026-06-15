# NexusCapture
An advanced Python packet sniffer featuring real-time interception, BPF filtering, and PCAP export.

NexusCapture - Advanced Protocol Analyzer

Python Version: 3.8+
Dependencies: Scapy
Platform: Windows, Linux, macOS

NexusCapture is a multi-threaded, desktop-based network packet sniffer built with Python. It provides real-time traffic interception, deep packet inspection, and packet capturing capabilities (PCAP) with a dark-mode graphical interface.

Unlike basic command-line sniffers, this application separates the packet interception engine from the UI rendering layer using asynchronous queues, ensuring the application remains responsive even under heavy network loads.


Key Features

Multi-Threaded Architecture: Utilizes Python's threading and queue modules to prevent UI lockup during high-volume traffic interception.

BPF (Berkeley Packet Filter) Support: Filter traffic natively at the capture level (e.g., icmp, tcp port 80, host 192.168.1.5) to reduce memory overhead and focus on relevant data.

Deep Packet Inspection (DPI): Automatically dissects OSI layers (Data Link, Network, Transport) and decodes raw application payloads (Plaintext, Hex dumps).

PCAP Exporting: Save captured sessions directly to standard .pcap files for later analysis in enterprise tools like Wireshark.

Memory Safe: Implements store=0 in the Scapy sniffing loop to prevent RAM leaks during extended capture sessions.

Prerequisites

To run this application, you must have the following installed:

Python 3.8+

Scapy library: pip install scapy

Hardware Driver (Windows Only): Windows users must install Npcap from npcap.com to allow Python to read raw network sockets. Ensure you check "Install Npcap in WinPcap API-compatible Mode" during installation.

Installation & Usage

Clone the repository:
git clone https://github.com/hamaadite/nexus-capture.git
cd nexus-capture

Install required dependencies:
pip install -r requirements.txt

Run with Elevated Privileges: Intercepting physical network interfaces requires root/administrator access.
Windows: Open Command Prompt as Administrator, then run: python packet_sniffer.py
Linux / macOS: Run: sudo python3 packet_sniffer.py

Testing the Sniffer

Once the UI is running, try these commands in a separate terminal to see the sniffer in action:

ICMP Traffic: ping 8.8.8.8 (Type icmp in the filter box before starting).

DNS/UDP Traffic: nslookup google.com

HTTP/TCP Traffic: Open a browser and navigate to http://neverssl.com to see raw, unencrypted HTML payloads in the deep inspection panel.

Ethical Disclaimer

This tool is built strictly for educational purposes, network diagnostics, and authorized penetration testing. Do not use this software to intercept traffic on networks where you do not have explicit permission from the network owner.
