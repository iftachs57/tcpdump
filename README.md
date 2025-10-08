# PCAP Analyzer Tool

A simple, interactive command-line tool for analyzing `.pcap` and `.pcapng` network capture files using **PyShark** and **Pydantic**.
It allows you to:

* View detailed reports of captured packets
* Count IP address occurrences
* Export the parsed data and statistics to a JSON file

---

## Installation

### Install dependencies

```bash

pip install -r requirements.txt

```

## Usage

Run the program from the root directory:

```bash

python main.py

```

You’ll see an interactive menu:

    Enter your choice:
    1) Enter pcap/pcapng file
    2) Print report on current file
    3) Export current Report as Json file
    4) Exit

### Enter file path

Input the full path to your `.pcap` or `.pcapng` file.

### View report

Generates a console report with:

* Packet number
* Timestamp
* Source/Destination IPs and ports
* Protocol, Plus, a summary of IP appearance counts.

### Export to JSON

Exports packet data and IP statistics to a JSON file.
You’ll be prompted for:

* Output directory
* Output file name

The generated JSON includes:

```json
{
  "packets": {
    "1": {
      "Num": 1,
      "Timestamp": "2024-01-01 10:00:00",
      "Source": "192.168.1.10",
      "Destination": "192.168.1.20",
      "SourcePort": "443",
      "DestinationPort": "51822",
      "Protocol": "TCP"
    }
  },
  "IP appearances": {
    "192.168.1.10": 5,
    "192.168.1.20": 5
  }
}
```

---

## Supported Protocols

| Protocol | Source Accessor                   | Destination Accessor              |
| -------- | --------------------------------- | --------------------------------- |
| TCP      | `p.tcp.srcport`                   | `p.tcp.dstport`                   |
| UDP      | `p.udp.srcport`                   | `p.udp.dstport`                   |
| ICMP     | `p.icmp.type`                     | `p.icmp.code`                     |
| TLS      | `p.tcp.srcport`                   | `p.tcp.dstport`                   |
| DNS      | `p.udp.srcport` / `p.tcp.srcport` | `p.udp.dstport` / `p.tcp.dstport` |

---

## Output Example

```
___________________________________________
Packet Num - 5
Timestamp - 2024-01-01 10:00:01
Source IP - 192.168.1.10 - SRCPort - 443
Destination - 192.168.1.20 - DSCPort - 51822
Protocol - TCP
___________________________________________
IP - 192.168.1.10 ,appeared - 5 times
IP - 192.168.1.20 ,appeared - 5 times
```

## Notes

* Non-IPv4 packets and unsupported protocols are logged as errors.
* If a packet is missing fields (timestamp, ports, IPs) a console message is printed.
* JSON export automatically creates the target folder if it doesn’t exist.
* Working with pcap and pcapng files (must common tcpdump files)
* Everything is in the consts file instead of an config.json file, for easier use and "out-of-the-box" product

