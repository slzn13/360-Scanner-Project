# 360-Scanner-Project
A Bash-based automation tool for analyzing Wireshark/Tshark-compatible .pcap files. Designed to streamline network traffic analysis, this project generates readable reports from raw captures, helping cybersecurity professionals and system administrators quickly extract key insights.


## Installation & Setup

### 1. Install Prerequisites
```bash
sudo apt update
sudo apt install tshark geoip-bin gnuplot pandoc python3-tk
```

### 2. Give Execute Permissions to the Script
```bash
chmod +x pcap_scanner.sh
```

### 3. Run the Script via Terminal
```bash
./pcap_scanner.sh /path/to/capture.pcap
```

### 4. Run with Python GUI
```bash
python3 pcap_scanner_gui.py
```
