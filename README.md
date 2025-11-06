# 360-Scanner-Project
A Bash-based automation tool for analyzing Wireshark/Tshark-compatible .pcap files. Designed to streamline network traffic analysis, this project generates readable reports from raw captures, helping cybersecurity professionals and system administrators quickly extract key insights.

Install prerequisites:
sudo apt update
sudo apt install tshark geoip-bin gnuplot pandoc
sudo apt install python3-tk

Give execute permissions to the script:
chmod +x pcap_scanner.sh

Running script in terminal:
./pcap_scanner.sh /path/to/capture.pcap

Running script with Python GUI:
python3 pcap_scanner_gui.py
