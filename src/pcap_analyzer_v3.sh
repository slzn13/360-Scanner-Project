#!/usr/bin/env bash
#
# pcap-analyzer.sh
# Bash-based automation tool for analyzing Wireshark/Tshark-compatible .pcap files.
# Generates a readable report from raw captures (offline or live).
#

set -euo pipefail

VERSION="2.0"

# Optional global display filter for tshark
FILTER=""

# Live capture options
LIVE_IFACE=""
LIVE_DURATION=5

#############################
# Utility / Requirements
#############################

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <capture.pcap>

Offline mode (analyze existing PCAP):
  $(basename "$0") traffic.pcap
  $(basename "$0") -o report.txt traffic.pcap
  $(basename "$0") -f "ip.addr == 10.0.0.5" traffic.pcap

Live mode (capture & analyze in a loop):
  $(basename "$0") --live eth0
  $(basename "$0") --live eth0 --duration 10
  $(basename "$0") --live eth0 -f "ip.addr == 10.0.0.5"

Options:
  -o, --output FILE     Write report to FILE instead of stdout (offline mode)
  -f, --filter EXPR     Apply a display filter (tshark -Y EXPR) to narrow analysis
  --live IFACE          Live capture mode on interface IFACE (no PCAP argument needed)
  --duration SECONDS    In live mode, per-capture window length (default: 5)
  -h, --help            Show this help message
  -v, --version         Show version

Description:
  A Bash-based automation tool for analyzing Wireshark/Tshark-compatible .pcap files.
  Designed to streamline network traffic analysis and generate readable reports
  from raw captures.

  Live mode uses tshark to capture short windows of traffic, runs the same
  analysis sections on each window, and refreshes continuously until Ctrl-C.

EOF
}

require_tshark() {
    if ! command -v tshark >/dev/null 2>&1; then
        echo "[ERROR] tshark is not installed or not in PATH." >&2
        echo "        This tool depends on tshark (the CLI version of Wireshark)." >&2
        echo "" >&2
        echo "Install suggestions:" >&2
        echo "  Debian/Ubuntu:  sudo apt-get update && sudo apt-get install tshark" >&2
        echo "  Fedora/RHEL:    sudo dnf install wireshark-cli" >&2
        echo "  Arch Linux:     sudo pacman -S wireshark-cli" >&2
        echo "" >&2
        exit 1
    fi
}

#############################
# Formatting
#############################

section_divider() {
    printf '\n============================================================\n\n'
}

print_header() {
    local pcap="$1"
    echo "Automated PCAP Analysis Report"
    echo "PCAP File : $pcap"
    echo "Generated : $(date)"
    echo "Tool      : pcap-analyzer.sh v${VERSION}"
}

#############################
# Sections
#############################

section_overview() {
    local pcap="$1"
    echo "=== Overview ==="

    # Total packets
    local total
    total=$(tshark -n -r "$pcap" 2>/dev/null | wc -l | tr -d ' ')
    echo "Total Packets: ${total:-unknown}"

    # Capture time range (approx)
    local first last duration
    first=$(tshark -n -r "$pcap" -T fields -e frame.time_epoch 2>/dev/null | head -n 1 || true)
    last=$(tshark -n -r "$pcap" -T fields -e frame.time_epoch 2>/dev/null | tail -n 1 || true)
    if [[ -n "${first:-}" && -n "${last:-}" ]]; then
        duration=$(awk -v f="$first" -v l="$last" 'BEGIN {d=l-f; if(d<0)d=0; printf "%.2f", d}')
        echo "Capture Start: $(date -d "@$first" 2>/dev/null || echo "$first")"
        echo "Capture End  : $(date -d "@$last" 2>/dev/null || echo "$last")"
        echo "Duration (s) : $duration"
    fi

    echo
    echo "--- Protocol Hierarchy (top 10) ---"
    tshark -n -r "$pcap" -q -z io,phs 2>/dev/null \
        | sed -n 's/^  / /p' \
        | head -n 12
}

section_endpoints() {
    local pcap="$1"
    echo "=== Endpoints (Top IP Endpoints) ==="
    tshark -n -r "$pcap" -q -z endpoints,ip 2>/dev/null \
        | sed -n '/IPv4/,/====/p' \
        | head -n 20
}

section_top_talkers() {
    local pcap="$1"
    echo "=== Top Talkers (src → dst by packet count) ==="

    local df
    if [[ -n "$FILTER" ]]; then
        df="$FILTER && ip.src && ip.dst"
    else
        df="ip.src && ip.dst"
    fi

    tshark -n -r "$pcap" -Y "$df" -T fields -e ip.src -e ip.dst 2>/dev/null \
        | awk 'NF==2 {print $1 " -> " $2}' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 15
}

section_ports() {
    local pcap="$1"
    echo "=== Top Ports (TCP/UDP) ==="

    echo "-- TCP Destination Ports --"
    local tcp_df
    if [[ -n "$FILTER" ]]; then
        tcp_df="$FILTER && tcp"
    else
        tcp_df="tcp"
    fi

    tshark -n -r "$pcap" -Y "$tcp_df" -T fields -e tcp.dstport 2>/dev/null \
        | awk 'NF==1 {print $1}' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 10

    echo
    echo "-- UDP Destination Ports --"
    local udp_df
    if [[ -n "$FILTER" ]]; then
        udp_df="$FILTER && udp"
    else
        udp_df="udp"
    fi

    tshark -n -r "$pcap" -Y "$udp_df" -T fields -e udp.dstport 2>/dev/null \
        | awk 'NF==1 {print $1}' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 10
}

section_http_summary() {
    local pcap="$1"
    echo "=== HTTP Summary ==="

    local http_df
    if [[ -n "$FILTER" ]]; then
        http_df="$FILTER && http.request"
    else
        http_df="http.request"
    fi

    echo "-- HTTP Hosts (Top 10) --"
    tshark -n -r "$pcap" -Y "$http_df" -T fields -e http.host 2>/dev/null \
        | sed '/^$/d' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 10

    echo
    echo "-- HTTP Request URLs (Top 10) --"
    tshark -n -r "$pcap" -Y "$http_df" -T fields -e http.host -e http.request.uri 2>/dev/null \
        | awk 'NF>=2 {printf "http://%s%s\n", $1, $2}' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 10

    echo
    echo "-- Possible Cleartext Credentials in HTTP (heuristic) --"
    local cred_df
    if [[ -n "$FILTER" ]]; then
        cred_df="$FILTER && (http.request.uri contains \"user\" or http.request.uri contains \"username\" or http.request.uri contains \"password\" or http.request.uri contains \"passwd\")"
    else
        cred_df="http.request.uri contains \"user\" or http.request.uri contains \"username\" or http.request.uri contains \"password\" or http.request.uri contains \"passwd\""
    fi

    tshark -n -r "$pcap" -Y "$cred_df" \
           -T fields -e frame.number -e ip.src -e ip.dst -e http.request.full_uri 2>/dev/null \
        | head -n 15
}

section_dns_summary() {
    local pcap="$1"
    echo "=== DNS Summary ==="

    local dns_df
    if [[ -n "$FILTER" ]]; then
        dns_df="$FILTER && dns.qry.name"
    else
        dns_df="dns.qry.name"
    fi

    echo "-- Top Queried Domains (Top 15) --"
    tshark -n -r "$pcap" -Y "$dns_df" -T fields -e dns.qry.name 2>/dev/null \
        | sed '/^$/d' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 15

    echo
    echo "-- Top DNS Querier IPs (Top 10) --"
    local dns_src_df
    if [[ -n "$FILTER" ]]; then
        dns_src_df="$FILTER && dns && ip.src"
    else
        dns_src_df="dns && ip.src"
    fi

    tshark -n -r "$pcap" -Y "$dns_src_df" -T fields -e ip.src 2>/dev/null \
        | sed '/^$/d' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 10

    echo
    echo "-- Suspicious-Looking DNS (heuristic: long or unusual) --"
    tshark -n -r "$pcap" -Y "$dns_df" -T fields -e frame.number -e ip.src -e dns.qry.name 2>/dev/null \
        | awk 'length($3) > 40' \
        | head -n 10
}

section_conversations() {
    local pcap="$1"
    echo "=== Conversations (Top by packets) ==="
    tshark -n -r "$pcap" -q -z conv,ip 2>/dev/null \
        | sed -n '/IPv4/,/====/p' \
        | head -n 20
}

section_heavy_conversations() {
    local pcap="$1"
    echo "=== Heavy Conversations (Bytes/Packets) ==="
    tshark -n -r "$pcap" -q -z conv,ip 2>/dev/null \
        | sed -n '/IPv4/,/====/p' \
        | head -n 30
}

section_tls_summary() {
    local pcap="$1"
    echo "=== TLS Summary ==="

    local tls_df
    if [[ -n "$FILTER" ]]; then
        tls_df="$FILTER && tls.handshake.extensions_server_name"
    else
        tls_df="tls.handshake.extensions_server_name"
    fi

    echo "-- TLS Server Names (Top 15) --"
    tshark -n -r "$pcap" -Y "$tls_df" \
           -T fields -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null \
        | sed '/^$/d' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 15
}

section_ftp_credentials() {
    local pcap="$1"
    echo "=== FTP Credentials (Plaintext) ==="

    local ftp_df
    if [[ -n "$FILTER" ]]; then
        ftp_df="$FILTER && (ftp.request.command == \"USER\" || ftp.request.command == \"PASS\")"
    else
        ftp_df="ftp.request.command == \"USER\" || ftp.request.command == \"PASS\""
    fi

    echo "-- Raw USER/PASS Commands (Top 20) --"
    tshark -n -r "$pcap" -Y "$ftp_df" \
           -T fields -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg 2>/dev/null \
        | head -n 20

    echo
    echo "-- Grouped Credentials by TCP Stream (Heuristic) --"
    tshark -n -r "$pcap" -Y "$ftp_df" \
           -T fields -E separator='|' \
           -e tcp.stream -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg 2>/dev/null \
        | sort -t '|' -k1,1 -k2,2n \
        | awk -F'|' '
            {
                stream=$1;
                cmd=$5;
                arg=$6;
                if (cmd == "USER") {
                    user[stream]=arg;
                } else if (cmd == "PASS") {
                    pass[stream]=arg;
                }
            }
            END {
                printf "%-10s %-20s %-20s\n", "STREAM", "USERNAME", "PASSWORD";
                printf "%-10s %-20s %-20s\n", "------", "--------", "--------";
                for (s in user) {
                    printf "%-10s %-20s %-20s\n", s, user[s], (s in pass ? pass[s] : "(none)");
                }
            }
        '
}

section_suspicious_patterns() {
    local pcap="$1"
    echo "=== Suspicious Traffic Indicators (Heuristic) ==="

    echo "-- HTTP containing 'login', 'admin', or 'token' --"
    local sus_http_df
    if [[ -n "$FILTER" ]]; then
        sus_http_df="$FILTER && (http contains \"login\" or http contains \"admin\" or http contains \"token\")"
    else
        sus_http_df="http contains \"login\" or http contains \"admin\" or http contains \"token\""
    fi

    tshark -n -r "$pcap" -Y "$sus_http_df" \
           -T fields -e frame.number -e ip.src -e ip.dst -e http.request.full_uri 2>/dev/null \
        | head -n 15

    echo
    echo "-- Possible Shell/Command Patterns in HTTP --"
    local shell_df
    if [[ -n "$FILTER" ]]; then
        shell_df="$FILTER && (http contains \"cmd=\" or http contains \"shell\")"
    else
        shell_df="http contains \"cmd=\" or http contains \"shell\""
    fi

    tshark -n -r "$pcap" -Y "$shell_df" \
           -T fields -e frame.number -e ip.src -e ip.dst -e http.request.full_uri 2>/dev/null \
        | head -n 10

    echo
    echo "-- Non-Standard TCP Ports with High Traffic (Top 10) --"
    local nonstd_df
    if [[ -n "$FILTER" ]]; then
        nonstd_df="$FILTER && tcp && tcp.dstport != 80 && tcp.dstport != 443"
    else
        nonstd_df="tcp && tcp.dstport != 80 && tcp.dstport != 443"
    fi

    tshark -n -r "$pcap" -Y "$nonstd_df" -T fields -e ip.src -e tcp.dstport 2>/dev/null \
        | awk 'NF==2 {print $1 ":" $2}' \
        | sort \
        | uniq -c \
        | sort -nr \
        | head -n 10
}

#############################
# Live Mode
#############################

live_mode() {
    local iface="$1"
    local duration="$2"

    require_tshark

    echo "[*] Live capture mode on interface '$iface' (window: ${duration}s, Ctrl-C to exit)"
    sleep 1

    while true; do
        local tmpfile
        tmpfile=$(mktemp /tmp/pcap-live.XXXXXX.pcap)

        if ! tshark -n -i "$iface" -a "duration:$duration" -w "$tmpfile" >/dev/null 2>&1; then
            echo "[ERROR] Failed to capture on interface '$iface'." >&2
            rm -f "$tmpfile"
            break
        fi

        clear
        print_header "$tmpfile"
        section_divider

        section_overview "$tmpfile"
        section_divider

        section_endpoints "$tmpfile"
        section_divider

        section_top_talkers "$tmpfile"
        section_divider

        section_ports "$tmpfile"
        section_divider

        section_http_summary "$tmpfile"
        section_divider

        section_dns_summary "$tmpfile"
        section_divider

        section_conversations "$tmpfile"
        section_divider

        section_suspicious_patterns "$tmpfile"
        section_divider

        section_ftp_credentials "$tmpfile"
        section_divider

        echo "[*] Live mode: interface=$iface, window=${duration}s (Ctrl-C to exit)"
        rm -f "$tmpfile"
    done
}

#############################
# Main
#############################

main() {
    local output=""
    local pcap=""

    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                if [[ $# -lt 2 ]]; then
                    echo "[ERROR] -o/--output requires a file argument." >&2
                    exit 1
                fi
                output="$2"
                shift 2
                ;;
            -f|--filter)
                if [[ $# -lt 2 ]]; then
                    echo "[ERROR] -f/--filter requires a filter expression." >&2
                    exit 1
                fi
                FILTER="$2"
                shift 2
                ;;
            --live)
                if [[ $# -lt 2 ]]; then
                    echo "[ERROR] --live requires an interface name." >&2
                    exit 1
                fi
                LIVE_IFACE="$2"
                shift 2
                ;;
            --duration)
                if [[ $# -lt 2 ]]; then
                    echo "[ERROR] --duration requires a number of seconds." >&2
                    exit 1
                fi
                LIVE_DURATION="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "pcap-analyzer.sh v${VERSION}"
                exit 0
                ;;
            -*)
                echo "[ERROR] Unknown option: $1" >&2
                usage
                exit 1
                ;;
            *)
                # Positional arg = pcap (offline mode)
                pcap="$1"
                shift
                ;;
        esac
    done

    # Live mode takes precedence and does NOT need a PCAP file
    if [[ -n "$LIVE_IFACE" ]]; then
        live_mode "$LIVE_IFACE" "$LIVE_DURATION"
        exit 0
    fi

    # Offline mode: need a PCAP path
    if [[ -z "$pcap" ]]; then
        echo "[ERROR] No PCAP file provided (and --live not specified)." >&2
        usage
        exit 1
    fi

    if [[ ! -r "$pcap" ]]; then
        echo "[ERROR] PCAP file not found or not readable: $pcap" >&2
        exit 1
    fi

    require_tshark

    # Decide where to send output (offline mode only)
    if [[ -n "$output" ]]; then
        exec >"$output"
    fi

    print_header "$pcap"
    section_divider

    section_overview "$pcap"
    section_divider

    section_endpoints "$pcap"
    section_divider

    section_top_talkers "$pcap"
    section_divider

    section_ports "$pcap"
    section_divider

    section_http_summary "$pcap"
    section_divider

    section_dns_summary "$pcap"
    section_divider

    section_conversations "$pcap"
    section_divider

    section_heavy_conversations "$pcap"
    section_divider

    section_tls_summary "$pcap"
    section_divider

    section_suspicious_patterns "$pcap"
    section_divider

    section_ftp_credentials "$pcap"
    section_divider

    echo "End of report."
}

main "$@"
