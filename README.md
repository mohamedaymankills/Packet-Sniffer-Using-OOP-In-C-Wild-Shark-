# WildShark - Packet Sniffer
!(1)[https://github.com/mohamedaymankills/Packet-Sniffer-Using-OOP-In-C-Wild-Shark-/blob/main/Screenshot%20from%202025-01-31%2020-09-37.png]
## Overview

**WildShark** is a lightweight packet sniffer implemented in **C** using `libpcap`. It captures network packets on a specified interface, decodes **IP, TCP, and UDP** headers, and provides filtering options for specific IPs or ports, similar to **Wireshark** or **TcpDump**.

## Features

- **Object-Oriented Programming (OOP) approach** in C.
- Captures and decodes **IP packets** and their headers.
- Supports **TCP, UDP, and ICMP** protocols.
- Extracts **source and destination IP addresses**.
- Displays **TCP/UDP source and destination ports**.
- Supports **filtering** by IP or port using command-line arguments.

## Dependencies

Make sure you have the following installed:

- `libpcap` (Packet capture library)
- `gcc` (GNU Compiler Collection)

Install dependencies on **Ubuntu**:

```sh
sudo apt update
sudo apt install libpcap-dev gcc
```

## Installation

Clone the repository and compile the code:

```sh
git clone https://github.com/mohamedaymankills/WildShark.git
cd WildShark
gcc -o Wild_Shark WildShark.c -lpcap
```

## Usage

Run the sniffer with **sudo** privileges:

```sh
sudo ./Wild_Shark <interface> <filter-expression>
```

### Example Commands

- Capture **all packets** on `eth0`:
  
  ```sh
  sudo ./Wild_Shark eth0 ""
  ```
  
- Capture traffic on **port 80** (HTTP):
  
  ```sh
  sudo ./Wild_Shark eth0 "port 80"
  ```
  
- Capture packets from/to a specific **IP**:
  
  ```sh
  sudo ./Wild_Shark eth0 "host 192.168.1.1"
  ```
  
- Capture **TCP packets** only:
  
  ```sh
  sudo ./Wild_Shark eth0 "tcp"
  ```

## How It Works

1. **Opens the network interface** in promiscuous mode.
2. **Applies the packet filter** (if provided).
3. **Captures packets** and identifies their **protocol** (TCP, UDP, or ICMP).
4. **Extracts packet details** (IP addresses, ports, etc.).
5. **Displays packet information** in the terminal.
6. **Frees allocated memory** and closes the sniffer.

## Output Example

```
IP Packet: 192.168.1.10 -> 8.8.8.8
TCP Packet: Src Port: 54321 -> Dst Port: 80
UDP Packet: Src Port: 6000 -> Dst Port: 53
```

## Troubleshooting

- **Permission Error:** Run with `sudo`.
- **Couldn't parse filter:** Ensure filter syntax is correct.
- **Interface Not Found:** Run `ip link show` to check available interfaces.

## Author

**Mohamed Ayman Mohamed Abdelaziz**

## License

**MIT License**
