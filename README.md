# Basic Network Sniffer

A lightweight, educational packet sniffing tool written in Python using the `scapy` library. This script captures network packets on a specified network adapter, parses protocol layers (IP, TCP, UDP, ICMP), and prints a safe hex/text preview of raw payloads.

---

## Technical Prerequisites

To capture raw network packets, your operating system requires lower-level packet capturing drivers:

### 1. Install Packet Capturing Drivers
- **Windows**: Install [Npcap](https://npcap.com/#download). Make sure to check the box: *"Install Npcap in WinPcap API-compatible Mode"* during installation.
- **Linux**: Install `libpcap` (usually pre-installed, or via `sudo apt-get install libpcap-dev`).
- **macOS**: Pre-installed.

### 2. Install Python Dependencies
Create a virtual environment (optional but recommended) and install `scapy`:
```bash
pip install scapy
```

---

## How to Run the Sniffer

> [!IMPORTANT]
> Packet sniffing requires administrative/root privileges to access raw network interfaces.

### On Windows
Open command prompt or PowerShell **as Administrator** and run:
```bash
python sniffer.py
```

### On Linux / macOS
Run with `sudo`:
```bash
sudo python3 sniffer.py
```

---

## Command Line Arguments

You can customize the capture behavior using parameters:

| Flag | Argument | Description |
|---|---|---|
| `-l` | None | List all active network interfaces. |
| `-i` | `INTERFACE` | Specify interface name (e.g., `eth0`, `Wi-Fi`). |
| `-c` | `COUNT` | Number of packets to capture (default is continuous). |
| `-f` | `FILTER` | BPF filter pattern (e.g., `'tcp'`, `'udp'`, `'icmp'`). |

### Examples:

1. **List all network interfaces**:
   ```bash
   python sniffer.py -l
   ```

2. **Capture 10 packets on a specific Wi-Fi interface**:
   ```bash
   python sniffer.py -i "Wi-Fi" -c 10
   ```

3. **Capture only TCP packets (e.g. port 80 HTTP web traffic)**:
   ```bash
   python sniffer.py -f "tcp port 80"
   ```

4. **Capture only ICMP (ping) requests/replies**:
   ```bash
   python sniffer.py -f "icmp"
   ```

---

## Ethical and Legal Use Warning

> [!CAUTION]
> This sniffer is intended strictly for educational, security auditing, and local network troubleshooting purposes. 
> Capturing packets on networks without explicit owner authorization is unauthorized, unethical, and violates computer crime laws (such as the CFAA in the United States and similar worldwide regulations). 
> **Only use this software on your own local loopback interfaces or networks you own.**
