# 360-Scanner-Project
A Bash-based automation tool for analyzing Wireshark/Tshark-compatible .pcap files. Designed to streamline network traffic analysis, this project generates readable reports from raw captures, helping cybersecurity professionals and system administrators quickly extract key insights.

## Demo Video
[![Watch the video](https://img.youtube.com/vi/mOEv5ExT0iY/hqdefault.jpg)](https://youtu.be/mOEv5ExT0iY)

## Installation & Setup

### 1. Install Prerequisites
```bash
sudo apt update
sudo apt install tshark python3-tk xdg-utils
```

### 2. Give Execute Permissions to the Script
```bash
chmod +x pcap_analyzer_v3.sh
```

### 3. Run the Script via Terminal
```bash
./pcap_analyzer_v3.sh /path/to/capture.pcap
```

### 4. Run with Python GUI
```bash
python3 analyzer-gui-v3.py
```
