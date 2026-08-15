# Recon Tools

Two small Python security tools built for learning + portfolio purposes:

1. **`port_scanner.py`** — a TCP connect-scan port scanner built from scratch using only Python's `socket` library (no nmap, no third-party scanning libs). Multithreaded, supports port ranges, and does optional banner grabbing.
2. **`recon_scanner.py`** — a recon automation tool that wraps `nmap` for port/service scanning and adds DNS-based subdomain enumeration, then compiles everything into a JSON + styled HTML report.

## ⚠️ Legal / Ethical Use Only

Only run these tools against systems you **own** or have **explicit written authorization** to test — your own lab VMs, or platforms built for this like [TryHackMe](https://tryhackme.com), [HackTheBox](https://hackthebox.com), or [scanme.nmap.org](https://scanme.nmap.org) (nmap's official test target). Unauthorized scanning may violate computer misuse laws in your jurisdiction (e.g. the CFAA in the US).

## Requirements

- Python 3.8+
- `nmap` installed and in your `PATH` (only required for `recon_scanner.py`)
  - Debian/Ubuntu: `sudo apt install nmap`
  - macOS: `brew install nmap`
## `port_scanner.py`

```bash
# Scan the first 1024 ports (default)
python3 port_scanner.py -t 192.168.1.10

# Scan a specific range with more threads
python3 port_scanner.py -t scanme.nmap.org -p 1-65535 --threads 200

# Scan specific ports only, with a tighter timeout
python3 port_scanner.py -t 10.0.0.5 -p 22,80,443,8080 --timeout 0.5

# Disable banner grabbing (faster, quieter)
python3 port_scanner.py -t 10.0.0.5 --no-banner
```

**How it works:** for each target port, it opens a raw TCP socket and calls `connect_ex()`. A return value of `0` means the full TCP three-way handshake completed — the port is open. This is a "full connect" scan (as opposed to a stealthier SYN/half-open scan, which needs raw sockets and root privileges). Ports are distributed across a thread pool for speed.

## `recon_scanner.py`

```bash
# Full recon: subdomain enum + nmap scan, output to recon_report.json/.html
python3 recon_scanner.py -t example.com

# Custom port range and your own subdomain wordlist
python3 recon_scanner.py -t example.com --ports 1-5000 --wordlist my_wordlist.txt

# Just the port scan, skip subdomain enumeration
python3 recon_scanner.py -t 192.168.1.10 --skip-subdomains

# Custom output filename
python3 recon_scanner.py -t example.com -o example_recon
```

**How it works:**
1. If the target looks like a domain, it brute-forces a subdomain wordlist (built-in default, or your own file) via DNS resolution.
2. It shells out to `nmap -sV` for a service/version-aware port scan, then parses the XML output.
3. Both results are merged into a single report, written as both machine-readable JSON and a styled, dark-mode HTML page.

## Roadmap / ideas for extending this

- [ ] Add SYN scan mode to `port_scanner.py` (requires raw sockets + root)
- [ ] Add certificate transparency log lookup (crt.sh) as an additional subdomain source
- [ ] Multi-target support (CIDR ranges, target lists)
- [ ] Screenshot web ports automatically (e.g. via headless Chrome)
- [ ] Export findings directly to a ticketing system / Slack webhook

## License

MIT — use freely, but see the legal notice above.
