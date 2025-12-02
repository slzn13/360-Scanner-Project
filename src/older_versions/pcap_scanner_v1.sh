#!/bin/bash

# Usage: ./pcap_scanner.sh <pcap_file> [-o output_dir] [-h]

# Function to display help
show_help() {
    echo "Usage: $0 <pcap_file> [-o output_dir] [-h]"
    echo "  -o: Specify output directory (default: ./report)"
    echo "  -h: Show this help message"
    exit 0
}

# Parse arguments
OUTPUT_DIR="./report"
while getopts "o:h" opt; do
    case $opt in
        o) OUTPUT_DIR="$OPTARG" ;;
        h) show_help ;;
        *) echo "Invalid option"; show_help ;;
    esac
done
shift $((OPTIND-1))

PCAP_FILE="$1"
if [ -z "$PCAP_FILE" ] || [ ! -f "$PCAP_FILE" ]; then
    echo "Error: Provide a valid .pcap file."
    show_help
fi

# Check for required tools
for tool in tshark geoiplookup gnuplot pandoc; do
    if ! command -v $tool &> /dev/null; then
        echo "Error: $tool is required but not installed."
        exit 1
    fi
done

# Create output directory
mkdir -p "$OUTPUT_DIR"
MD_FILE="$OUTPUT_DIR/report.md"
PDF_FILE="$OUTPUT_DIR/report.pdf"
echo "# PCAP Analysis Report for $PCAP_FILE" > "$MD_FILE"

# Basic information
echo "## Basic Information" >> "$MD_FILE"
FILE_SIZE=$(du -h "$PCAP_FILE" | cut -f1)
PACKET_COUNT=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
START_TIME=$(tshark -r "$PCAP_FILE" -t ad -c 1 -T fields -e frame.time 2>/dev/null)
END_TIME=$(tshark -r "$PCAP_FILE" -t ad -T fields -e frame.time 2>/dev/null | tail -1)
DURATION=$(echo $(date -d "$END_TIME" +%s) - $(date -d "$START_TIME" +%s) | bc) seconds
echo "- File Size: $FILE_SIZE" >> "$MD_FILE"
echo "- Packet Count: $PACKET_COUNT" >> "$MD_FILE"
echo "- Capture Duration: $DURATION" >> "$MD_FILE"
echo "- Start Time: $START_TIME" >> "$MD_FILE"
echo "- End Time: $END_TIME" >> "$MD_FILE"

# Protocols, Hosts, Ports
echo "## Protocols, Hosts, and Ports" >> "$MD_FILE"
tshark -r "$PCAP_FILE" -q -z io,phs >> "$MD_FILE"

# Top IPs
echo "## Top Active IP Addresses" >> "$MD_FILE"
TOP_IPS_FILE="$OUTPUT_DIR/top_ips.txt"
tshark -r "$PCAP_FILE" -T fields -e ip.src -e ip.dst 2>/dev/null | awk '{print $1"\n"$2}' | grep -v "^$" | sort | uniq -c | sort -nr | head -10 > "$TOP_IPS_FILE"
cat "$TOP_IPS_FILE" | awk '{print "- " $2 ": " $1 " packets"}' >> "$MD_FILE"

# Geolocation
echo "### Geolocation of Top IPs" >> "$MD_FILE"
while read -r line; do
    IP=$(echo $line | awk '{print $2}')
    GEO=$(geoiplookup $IP 2>/dev/null | grep "GeoIP Country" | cut -d: -f2-)
    echo "- $IP: $GEO" >> "$MD_FILE"
done < "$TOP_IPS_FILE"

# Top HTTP Hosts
echo "## Top Requested HTTP Hosts" >> "$MD_FILE"
tshark -r "$PCAP_FILE" -Y http.request -T fields -e http.host 2>/dev/null | sort | uniq -c | sort -nr | head -10 | awk '{print "- " $2 ": " $1 " requests"}' >> "$MD_FILE"

# DNS Queries
echo "## DNS Queries" >> "$MD_FILE"
DNS_FILE="$OUTPUT_DIR/dns_queries.txt"
tshark -r "$PCAP_FILE" -Y dns -T fields -e dns.qry.name 2>/dev/null | sort | uniq > "$DNS_FILE"
cat "$DNS_FILE" | head -20 | awk '{print "- " $0}' >> "$MD_FILE"
echo "(Showing top 20; full list in dns_queries.txt)" >> "$MD_FILE"

# Credential Scan (basic HTTP)
echo "## Potential Credentials" >> "$MD_FILE"
tshark -r "$PCAP_FILE" -Y "http contains \"password\" or http contains \"user\" or http contains \"login\"" -T fields -e http.request.uri -e http.request.full_uri 2>/dev/null | uniq | awk '{print "- Suspicious URI: " $0}' >> "$MD_FILE"
echo "(Note: This is a basic scan; review manually for false positives.)" >> "$MD_FILE"

# Scan Detection (e.g., SYN scans)
echo "## Potential Scans" >> "$MD_FILE"
tshark -r "$PCAP_FILE" -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.src -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -nr | head -10 | awk '{print "- From " $2 " to port " $3 ": " $1 " SYN packets"}' >> "$MD_FILE"
echo "(High SYN without ACK may indicate port scans.)" >> "$MD_FILE"

# Graphs
echo "## Visualizations" >> "$MD_FILE"

# Top IPs Graph
GNUPLOT_SCRIPT="$OUTPUT_DIR/top_ips.gnu"
echo "set terminal png size 800,600" > "$GNUPLOT_SCRIPT"
echo "set output '$OUTPUT_DIR/top_ips.png'" >> "$GNUPLOT_SCRIPT"
echo "set style data histogram" >> "$GNUPLOT_SCRIPT"
echo "set style fill solid" >> "$GNUPLOT_SCRIPT"
echo "set xtics rotate by -45" >> "$GNUPLOT_SCRIPT"
echo "plot '-' using 1:xtic(2) title 'Top IPs'" >> "$GNUPLOT_SCRIPT"
cat "$TOP_IPS_FILE" | awk '{print $1 " \"" $2 "\""}' >> "$GNUPLOT_SCRIPT"
echo "e" >> "$GNUPLOT_SCRIPT"
gnuplot "$GNUPLOT_SCRIPT"
echo "![Top IPs]($OUTPUT_DIR/top_ips.png)" >> "$MD_FILE"

# Generate PDF
pandoc "$MD_FILE" -o "$PDF_FILE" --from markdown --to pdf -V geometry:margin=1in

echo "Analysis complete. Report saved to $PDF_FILE"
