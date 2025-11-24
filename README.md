# Network Discovery Tool

Fast, comprehensive network enumeration tool for security assessments. Combines passive packet capture with active nmap scanning to quickly identify all live hosts on internal networks.

## Features

- **Passive Discovery**: Extract IPs from pcap files (IP, ARP, DNS, DHCP layers)
- **Active Scanning**: Concurrent nmap ping sweeps with multiple detection methods
- **Smart Targeting**: Auto-discovers subnets from traffic + scans baseline ranges
- **Live Progress**: Real-time progress display with stats and active targets
- **Fast**: Concurrent workers, configurable scan rates, and smart prioritization
- **Detailed Output**: Color-coded summaries, per-target statistics, and machine-readable results

## Quick Start

### Basic Usage (Live Capture)
```bash
# Capture 60 seconds of traffic on eth0, then scan discovered networks
sudo python3 Net-Discovery.py --iface eth0

# Faster scan with more workers and higher packet rate
sudo python3 Net-Discovery.py --iface eth0 --workers 16 --min-rate 1000
```

### Using Existing Pcap
```bash
# Analyze existing capture file
python3 Net-Discovery.py --pcap capture.pcapng

# Extract maximum detail (DNS + DHCP)
python3 Net-Discovery.py --pcap capture.pcapng --extract-dns --extract-dhcp
```

### Recommended On-Site Settings
```bash
# Fast enumeration for on-site assessments
sudo python3 Net-Discovery.py --iface eth0 \
  --duration 120 \
  --workers 16 \
  --min-rate 1000 \
  --ping-method aggressive \
  --prioritize-discovered \
  --extract-dhcp
```

## Command-Line Options

### Capture Options
- `--iface IFACE` - Network interface to capture from (e.g., eth0, wlan0)
- `--pcap PCAP` - Use existing pcap file instead of live capture
- `--duration DURATION` - Capture duration in seconds (default: 60)
- `--snaplen SNAPLEN` - Packet snap length in bytes (default: 256)

### Scanning Options
- `--workers WORKERS` - Max concurrent nmap workers (default: 8, recommend 16+ for speed)
- `--min-rate MIN_RATE` - Nmap packet rate per second (default: 300, use 1000+ for fast scans)
- `--host-timeout HOST_TIMEOUT` - Nmap timeout per host in seconds (default: 90)
- `--per-target-timeout PER_TARGET_TIMEOUT` - Subprocess timeout per subnet (default: 180)
- `--max-retries MAX_RETRIES` - Nmap retry attempts (default: 1)

### Detection Methods
- `--ping-method METHOD` - Choose ping method:
  - `default` - ICMP echo only (standard)
  - `aggressive` - ICMP + TCP SYN + ARP (best coverage, recommended)
  - `stealth` - TCP SYN only to common ports (quieter)
  - `arp-only` - ARP only (fastest for local networks)

### Extraction Options
- `--extract-dns` - Extract IPs from DNS responses (finds internal DNS records)
- `--extract-dhcp` - Extract IPs from DHCP packets (finds DHCP servers, gateways, assigned IPs)
- `--prefix PREFIX` - Aggregate discovered IPs into /PREFIX subnets (default: 24)

### Targeting Options
- `--extra-cidr CIDR` - Add manual CIDR ranges (can specify multiple times)
- `--prioritize-discovered` - Scan discovered subnets first (recommended for speed)

### Output Options
- `--outdir OUTDIR` - Output directory (default: recon_out)
- `--label LABEL` - Optional label for output filenames
- `--no-color` - Disable ANSI colors

## Output Files

All output is saved to `recon_out/` (or specified `--outdir`):

- **network_TIMESTAMP.txt** - List of live IPv4 addresses (one per line, sorted)
- **capture_TIMESTAMP.pcapng** - Packet capture (if using `--iface`)

## Examples

### Example 1: Quick 2-minute scan
```bash
sudo python3 Net-Discovery.py --iface eth0 --duration 120 --workers 12
```

### Example 2: Maximum coverage (slower)
```bash
sudo python3 Net-Discovery.py --iface eth0 \
  --duration 180 \
  --ping-method aggressive \
  --extract-dns \
  --extract-dhcp \
  --workers 16 \
  --min-rate 500
```

### Example 3: Stealth scan
```bash
sudo python3 Net-Discovery.py --iface eth0 \
  --duration 120 \
  --ping-method stealth \
  --min-rate 100 \
  --workers 4
```

### Example 4: Analyze existing capture with custom ranges
```bash
python3 Net-Discovery.py --pcap old_capture.pcap \
  --extra-cidr 10.50.0.0/16 \
  --extra-cidr 172.20.0.0/16 \
  --prioritize-discovered
```

### Example 5: Fast local network scan (ARP only)
```bash
sudo python3 Net-Discovery.py --iface eth0 \
  --duration 60 \
  --ping-method arp-only \
  --workers 20 \
  --min-rate 2000
```

## How It Works

1. **Passive Capture**: Captures network traffic using tshark
2. **IP Extraction**: Extracts IPs from multiple protocol layers:
   - IP layer (ip.src, ip.dst)
   - ARP layer (arp.src.proto_ipv4, arp.dst.proto_ipv4)
   - DNS layer (dns.a - optional with `--extract-dns`)
   - DHCP layer (dhcp.* - optional with `--extract-dhcp`)
3. **Subnet Aggregation**: Groups discovered IPs into /24 subnets (or custom prefix)
4. **Target Selection**: Combines discovered subnets + baseline ranges
5. **Concurrent Scanning**: Runs multiple nmap workers in parallel
6. **Live Hosts**: Outputs deduplicated list of live IPs

## Default Baseline Ranges

The tool always scans these baseline ranges in addition to discovered subnets:
- 10.1.0.0/16
- 10.10.0.0/16
- 10.50.0.0/16
- 10.100.0.0/16
- 172.16.0.0/16
- 172.132.0.0/16
- 192.168.0.0/16

Use `--extra-cidr` to add more ranges.

## Requirements

- Python 3.6+
- tshark (from Wireshark)
- nmap
- Root/sudo access for live capture

Install dependencies:
```bash
# Debian/Ubuntu
sudo apt-get install tshark nmap python3

# RedHat/CentOS
sudo yum install wireshark nmap python3

# macOS
brew install wireshark nmap python3
```

## Performance Tips

### For Speed (Fast On-Site Enumeration)
- Increase workers: `--workers 16` or higher
- Increase scan rate: `--min-rate 1000` or `--min-rate 2000`
- Use aggressive ping: `--ping-method aggressive`
- Prioritize discovered: `--prioritize-discovered`
- Shorter capture: `--duration 60` or `--duration 90`

### For Coverage (Thorough Assessment)
- Longer capture: `--duration 180` or `--duration 300`
- Extract all protocols: `--extract-dns --extract-dhcp`
- Multiple ping methods: Try `aggressive` then `stealth`
- More retries: `--max-retries 2`
- Lower rate for stealth: `--min-rate 100`

### For Stealth
- Use stealth method: `--ping-method stealth`
- Lower packet rate: `--min-rate 50`
- Fewer workers: `--workers 2`
- Longer timeouts: `--host-timeout 180`

## Troubleshooting

### "tshark not found in PATH"
Install Wireshark/tshark:
```bash
sudo apt-get install tshark
```

### "nmap not found"
Install nmap:
```bash
sudo apt-get install nmap
```

### Permission denied when capturing
Run with sudo:
```bash
sudo python3 Net-Discovery.py --iface eth0
```

### Scans timing out on large networks
Increase timeouts and rate:
```bash
python3 Net-Discovery.py --pcap file.pcap \
  --per-target-timeout 300 \
  --host-timeout 120 \
  --min-rate 500
```

### Not finding all hosts
Try aggressive ping method:
```bash
python3 Net-Discovery.py --pcap file.pcap --ping-method aggressive
```

## License

See LICENSE file for details.

## Contributing

Contributions welcome! Please submit pull requests or open issues for bugs/features.
