#!/usr/bin/env bash
#
# pcap-analyzer.sh
# Bash automation tool to analyze PCAP files (offline or live) using tshark.
# Produces human-readable network traffic reports or continuous live capture summaries.
#

set -euo pipefail  # safer bash: exit on errors, undefined variables, pipe failures

VERSION="2.0"

# Optional tshark display filter (e.g., -f "ip.addr == 10.0.0.5")
FILTER=""

# Live capture defaults
LIVE_IFACE=""
LIVE_DURATION=5

#############################
# Usage / Requirements
#############################

# Print usage/help
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <capture.pcap>
...
EOF
}

# Require tshark to exist
require_tshark() {
    if ! command -v tshark >/dev/null 2>&1; then
        echo "[ERROR] tshark is not installed." >&2
        exit 1
    fi
}

#############################
# Formatting Helpers
#############################

# Divider between report sections
section_divider() {
    printf '\n============================================================\n\n'
}

# Print header info for a report
print_header() {
    local pcap="$1"
    echo "Automated PCAP Analysis Report"
    echo "PCAP File : $pcap"
    echo "Generated : $(date)"
    echo "Tool      : pcap-analyzer.sh v${VERSION}"
}

#############################
# Analysis Sections
#############################

# 1. Overview: packet count, timestamps, protocol hierarchy
section_overview() {
    local pcap="$1"
    echo "=== Overview ==="

    # Get total packets by line count
    local total
    total=$(tshark -n -r "$pcap" 2>/dev/null | wc -l | tr -d ' ')
    echo "Total Packets: ${total:-unknown}"

    # Determine capture time range
    local first last duration
    first=$(tshark -n -r "$pcap" -T fields -e frame.time_epoch | head -n 1 || true)
    last=$(tshark -n -r "$pcap" -T fields -e frame.time_epoch | tail -n 1 || true)

    if [[ -n "$first" && -n "$last" ]]; then
        duration=$(awk -v f="$first" -v l="$last" 'BEGIN {d=l-f; if(d<0)d=0; printf "%.2f", d}')
        echo "Capture Start: $(date -d "@$first" 2>/dev/null || echo "$first")"
        echo "Capture End  : $(date -d "@$last" 2>/dev/null || echo "$last")"
        echo "Duration (s) : $duration"
    fi

    echo
    echo "--- Protocol Hierarchy (top 10) ---"
    tshark -n -r "$pcap" -q -z io,phs \
        | sed -n 's/^  / /p' \
        | head -n 12
}

# 2. Endpoint listing summary
section_endpoints() {
    local pcap="$1"
    echo "=== Endpoints (Top IP Endpoints) ==="
    tshark -n -r "$pcap" -q -z endpoints,ip \
        | sed -n '/IPv4/,/====/p' \
        | head -n 20
}

# 3. Identify top talkers by ip.src → ip.dst
section_top_talkers() {
    local pcap="$1"
    echo "=== Top Talkers (src → dst by packet count) ==="

    local df="${FILTER:+$FILTER && }ip.src && ip.dst"

    tshark -n -r "$pcap" -Y "$df" -T fields -e ip.src -e ip.dst \
        | awk 'NF==2 {print $1 " -> " $2}' \
        | sort | uniq -c | sort -nr | head -n 15
}

# 4. List top TCP & UDP ports
section_ports() {
    local pcap="$1"
    echo "=== Top Ports (TCP/UDP) ==="

    echo "-- TCP Destination Ports --"
    local tcp_df="${FILTER:+$FILTER && }tcp"

    tshark -n -r "$pcap" -Y "$tcp_df" -T fields -e tcp.dstport \
        | awk 'NF==1 {print $1}' \
        | sort | uniq -c | sort -nr | head -n 10

    echo
    echo "-- UDP Destination Ports --"
    local udp_df="${FILTER:+$FILTER && }udp"

    tshark -n -r "$pcap" -Y "$udp_df" -T fields -e udp.dstport \
        | awk 'NF==1 {print $1}' \
        | sort | uniq -c | sort -nr | head -n 10
}

# 5. HTTP analysis: hosts, URLs, plaintext creds
section_http_summary() {
    local pcap="$1"
    echo "=== HTTP Summary ==="

    local http_df="${FILTER:+$FILTER && }http.request"

    echo "-- HTTP Hosts (Top 10) --"
    tshark -n -r "$pcap" -Y "$http_df" -T fields -e http.host \
        | sed '/^$/d' | sort | uniq -c | sort -nr | head -n 10

    echo
    echo "-- HTTP Request URLs (Top 10) --"
    tshark -n -r "$pcap" -Y "$http_df" -T fields -e http.host -e http.request.uri \
        | awk 'NF>=2 {printf "http://%s%s\n", $1, $2}' \
        | sort | uniq -c | sort -nr | head -n 10

    echo
    echo "-- Possible Cleartext Credentials ---"
    local cred_df="${FILTER:+$FILTER && }(http.request.uri contains \"user\" or http.request.uri contains \"username\" or http.request.uri contains \"password\" or http.request.uri contains \"passwd\")"

    tshark -n -r "$pcap" -Y "$cred_df" \
        -T fields -e frame.number -e ip.src -e ip.dst -e http.request.full_uri \
        | head -n 15
}

# 6. DNS queries summary
section_dns_summary() {
    local pcap="$1"
    echo "=== DNS Summary ==="

    local dns_df="${FILTER:+$FILTER && }dns.qry.name"

    echo "-- Top Queried Domains --"
    tshark -n -r "$pcap" -Y "$dns_df" -T fields -e dns.qry.name \
        | sed '/^$/d' | sort | uniq -c | sort -nr | head -n 15

    echo
    echo "-- Top DNS Querier IPs --"
    local dns_src_df="${FILTER:+$FILTER && }dns && ip.src"

    tshark -n -r "$pcap" -Y "$dns_src_df" -T fields -e ip.src \
        | sed '/^$/d' | sort | uniq -c | sort -nr | head -n 10

    echo
    echo "-- Suspicious DNS (long domains) --"
    tshark -n -r "$pcap" -Y "$dns_df" -T fields -e frame.number -e ip.src -e dns.qry.name \
        | awk 'length($3) > 40' | head -n 10
}

# 7. Conversations summary
section_conversations() {
    local pcap="$1"
    echo "=== Conversations (Top by packets) ==="
    tshark -n -r "$pcap" -q -z conv,ip \
        | sed -n '/IPv4/,/====/p' \
        | head -n 20
}

section_heavy_conversations() {
    local pcap="$1"
    echo "=== Heavy Conversations (Bytes/Packets) ==="
    tshark -n -r "$pcap" -q -z conv,ip \
        | sed -n '/IPv4/,/====/p' \
        | head -n 30
}

# 8. TLS SNI extraction
section_tls_summary() {
    local pcap="$1"
    echo "=== TLS Summary ==="

    local tls_df="${FILTER:+$FILTER && }tls.handshake.extensions_server_name"

    echo "-- TLS Server Names --"
    tshark -n -r "$pcap" -Y "$tls_df" \
        -T fields -e ip.dst -e tls.handshake.extensions_server_name \
        | sed '/^$/d' | sort | uniq -c | sort -nr | head -n 15
}

# 9. FTP plaintext credential extraction
section_ftp_credentials() {
    local pcap="$1"
    echo "=== FTP Credentials (Plaintext) ==="

    local ftp_df="${FILTER:+$FILTER && }(ftp.request.command == \"USER\" || ftp.request.command == \"PASS\")"

    echo "-- Raw USER/PASS Commands --"
    tshark -n -r "$pcap" -Y "$ftp_df" \
        -T fields -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg \
        | head -n 20

    echo
    echo "-- Grouped Credentials by TCP Stream --"

    # Reconstruct USER/PASS pairs grouped by stream
    tshark -n -r "$pcap" -Y "$ftp_df" \
        -T fields -E separator='|' \
        -e tcp.stream -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg \
        | sort -t '|' -k1,1 -k2,2n \
        | awk -F'|' '
            {
                stream=$1; cmd=$5; arg=$6;
                if (cmd=="USER") user[stream]=arg;
                else if (cmd=="PASS") pass[stream]=arg;
            }
            END {
                printf "%-10s %-20s %-20s\n","STREAM","USERNAME","PASSWORD";
                for (s in user) printf "%-10s %-20s %-20s\n",s,user[s],(s in pass?pass[s]:"(none)");
            }
        '
}

# 10. Misc suspicious indicators
section_suspicious_patterns() {
    local pcap="$1"
    echo "=== Suspicious Traffic Indicators ==="

    echo "-- HTTP containing login/admin/token --"
    local sus_http_df="${FILTER:+$FILTER && }(http contains \"login\" or http contains \"admin\" or http contains \"token\")"

    tshark -n -r "$pcap" -Y "$sus_http_df" \
        -T fields -e frame.number -e ip.src -e ip.dst -e http.request.full_uri \
        | head -n 15

    echo
    echo "-- Possible shell commands inside HTTP --"
    local shell_df="${FILTER:+$FILTER && }(http contains \"cmd=\" or http contains \"shell\")"

    tshark -n -r "$pcap" -Y "$shell_df" \
        -T fields -e frame.number -e ip.src -e ip.dst -e http.request.full_uri \
        | head -n 10

    echo
    echo "-- High-traffic Non-Standard TCP Ports --"
    local nonstd_df="${FILTER:+$FILTER && }tcp && tcp.dstport != 80 && tcp.dstport != 443"

    tshark -n -r "$pcap" -Y "$nonstd_df" -T fields -e ip.src -e tcp.dstport \
        | awk 'NF==2 {print $1 ":" $2}' \
        | sort | uniq -c | sort -nr | head -n 10
}

#############################
# Live Mode Capturing
#############################

# Live capture loop: short PCAPs → analysis → repeat
live_mode() {
    local iface="$1"
    local duration="$2"

    require_tshark

    echo "[*] Live capture mode on '$iface' (window: ${duration}s)"

    while true; do
        # Temporary PCAP per capture window
        local tmpfile
        tmpfile=$(mktemp /tmp/pcap-live.XXXXXX.pcap)

        # Capture using tshark
        if ! tshark -n -i "$iface" -a "duration:$duration" -w "$tmpfile" >/dev/null; then
            echo "[ERROR] Capture failed."
            rm -f "$tmpfile"
            break
        fi

        # Clear screen and print new report
        clear
        print_header "$tmpfile"
        section_divider

        section_overview "$tmpfile";              section_divider
        section_endpoints "$tmpfile";             section_divider
        section_top_talkers "$tmpfile";           section_divider
        section_ports "$tmpfile";                 section_divider
        section_http_summary "$tmpfile";          section_divider
        section_dns_summary "$tmpfile";           section_divider
        section_conversations "$tmpfile";         section_divider
        section_suspicious_patterns "$tmpfile";   section_divider
        section_ftp_credentials "$tmpfile";       section_divider

        echo "[*] Live mode: window=${duration}s (Ctrl-C to exit)"

        rm -f "$tmpfile"  # cleanup
    done
}

#############################
# Main Program
#############################

main() {
    local output=""
    local pcap=""

    # Parse CLI options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)   output="$2"; shift 2 ;;
            -f|--filter)   FILTER="$2"; shift 2 ;;
            --live)        LIVE_IFACE="$2"; shift 2 ;;
            --duration)    LIVE_DURATION="$2"; shift 2 ;;
            -h|--help)     usage; exit 0 ;;
            -v|--version)  echo "pcap-analyzer.sh v${VERSION}"; exit 0 ;;
            -*)
                echo "[ERROR] Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                pcap="$1"
                shift
                ;;
        esac
    done

    # Live mode does not require a PCAP input
    if [[ -n "$LIVE_IFACE" ]]; then
        live_mode "$LIVE_IFACE" "$LIVE_DURATION"
        exit 0
    fi

    # Offline mode: ensure PCAP file is provided
    if [[ -z "$pcap" ]]; then
        echo "[ERROR] No PCAP provided."
        usage
        exit 1
    fi

    # Validate PCAP
    if [[ ! -r "$pcap" ]]; then
        echo "[ERROR] Cannot read PCAP: $pcap"
        exit 1
    fi

    require_tshark

    # If output file specified: send stdout to that file
    if [[ -n "$output" ]]; then
        exec >"$output"
    fi

    # Generate full offline report
    print_header "$pcap";                   section_divider
    section_overview "$pcap";               section_divider
    section_endpoints "$pcap";              section_divider
    section_top_talkers "$pcap";            section_divider
    section_ports "$pcap";                  section_divider
    section_http_summary "$pcap";           section_divider
    section_dns_summary "$pcap";            section_divider
    section_conversations "$pcap";          section_divider
    section_heavy_conversations "$pcap";    section_divider
    section_tls_summary "$pcap";            section_divider
    section_suspicious_patterns "$pcap";    section_divider
    section_ftp_credentials "$pcap";        section_divider

    echo "End of report."
}

main "$@"
