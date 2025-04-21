# Python Route - Enhanced Traceroute Tool

A powerful Python implementation of traceroute with additional network diagnostics and visualization features.

## Features

- 🚀 Traditional traceroute functionality with ICMP probes
- 🌍 IP geolocation lookup (city, country, ASN)
- ⏱️ Round-trip time statistics (average, standard deviation)
- 📊 Packet loss percentage per hop
- 🎨 Color-coded output with intuitive symbols
- 🔍 Reverse DNS lookup for each hop
- 💾 Caching to avoid redundant API calls
- 🛡️ Abuse contact information for suspicious IPs

## Requirements

- Python 3.6+
- Required packages:
  - `scapy`
  - `requests`
  - `colorama`
  - `pyfiglet` 

## Installation

1. Clone this repository or download the script:
   ```bash
   git clone https://github.com/WizardBitter/pythonroute.git
   cd python-route

2. Run Script
   `sudo python3 pythonroute.py`
