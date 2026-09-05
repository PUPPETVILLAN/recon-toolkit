# Recon Tools

Two versatile Python reconnaissance and network enumeration tools built for learning, auditing, and infrastructure discovery:

1. **`port_scanner.py`** — a high-speed TCP connect port scanner built from scratch using only Python's standard library (no nmap, zero third-party pip dependencies). Supports multi-target/CIDR scanning, top-ports presets, banner grabbing (SSH, FTP, HTTP, and TLS/SSL), and JSON/CSV reporting.
2. **`recon_scanner.py`** — an automated reconnaissance pipeline combining Certificate Transparency log lookup (`crt.sh`), DNS brute-forcing, `nmap -sV` service scanning, and automated HTTP title/server probing into structured JSON and an interactive dark-mode HTML dashboard with real-time filtering.

---

## ⚠️ Legal / Ethical Use Only

Only run these tools against systems you **own** or have **explicit written authorization** to test — your own lab VMs, local environments, or platforms built for this like [TryHackMe](https://tryhackme.com), [HackTheBox](https://hackthebox.com), or [scanme.nmap.org](https://scanme.nmap.org). Unauthorized scanning may violate computer misuse laws in your jurisdiction (e.g. the CFAA in the US).

---

## Requirements

- Python 3.8+ (No third-party `pip` packages required — pure standard library)
- `nmap` installed and in your `PATH` (only required for `recon_scanner.py`)
  - Debian/Ubuntu: `sudo apt install nmap`
  - Arch Linux: `sudo pacman -S nmap`
  - macOS: `brew install nmap`

---

## 1. `port_scanner.py`

### Usage Examples

```bash
# Scan default top ports (1-1024)
python3 port_scanner.py -t 192.168.1.10

# Fast scan using top-100 ports preset
python3 port_scanner.py -t scanme.nmap.org --top-ports 100

# Scan specific ports with custom thread count and timeout
python3 port_scanner.py -t 10.0.0.5 -p 22,80,443,8080 --threads 200 --timeout 0.5

# Multi-target scan using CIDR range
python3 port_scanner.py -t 192.168.1.0/28 -p 80,443,22

# Multi-target scan using a target list file
python3 port_scanner.py -iL targets.txt --top-ports 20

# Export results to JSON and CSV
python3 port_scanner.py -t scanme.nmap.org --top-ports 100 -oJ scan.json -oC scan.csv

# Disable banner grabbing (faster, quieter)
python3 port_scanner.py -t 10.0.0.5 --no-banner
```

### Features & How it works
- **Pure Python standard library**: Zero pip dependencies.
- **Multi-target & CIDR support**: Accepts single hosts, comma-separated lists, CIDR blocks (e.g. `192.168.1.0/28`), or target files (`-iL`).
- **Top-Ports Presets**: Instant `--top-ports 20` or `--top-ports 100` scans.
- **Smart Banner Grabbing**:
  - Reads initial service greeting for banner-on-connect protocols (SSH, FTP, SMTP).
  - Sends HTTP `HEAD` probes for web ports to extract the `Server:` response header.
  - Negotiates TLS/SSL handshakes for secure ports (HTTPS, SMTPS, IMAPS) to capture certificate information.
- **Export Formats**: Structured JSON (`-oJ`) and CSV (`-oC`).

---

## 2. `recon_scanner.py`

### Usage Examples

```bash
# Full recon: crt.sh + DNS brute-force + nmap service scan + HTTP probing
python3 recon_scanner.py -t example.com

# Passive Certificate Transparency lookup only (skips DNS brute-forcing)
python3 recon_scanner.py -t example.com --crt-only

# DNS brute-force with a custom wordlist (disabling crt.sh)
python3 recon_scanner.py -t example.com --no-crt --wordlist subdomains.txt

# Custom port range and custom output filenames
python3 recon_scanner.py -t example.com --ports 1-5000 -o example_recon

# Multi-target recon from a file
python3 recon_scanner.py -iL domains.txt --ports 80,443,8080

# Port scan only without subdomain enumeration
python3 recon_scanner.py -t 192.168.1.10 --skip-subdomains
```

### Features & How it works
1. **Passive Certificate Transparency (`crt.sh`)**: Queries public CT logs via HTTPS API to extract historical and active subdomains with zero active probing against the target domain.
2. **DNS Subdomain Enumeration**: Concurrently resolves subdomain candidates across customizable worker threads.
3. **Source Tagging**: Every discovered subdomain is tagged with its source (`crt.sh`, `DNS Brute-force`, or both).
4. **Service & Version Scanning**: Shells out to `nmap -sV` for accurate port/service/version fingerprinting.
5. **HTTP & Web Probing**: Probes discovered web services to automatically record HTTP status codes, page titles (`<title>`), and server headers.
6. **Interactive Dark-Mode HTML Report**:
   - Modern, responsive dark UI.
   - Real-time client-side search box to instantly filter subdomains, IP addresses, ports, and services.
   - Summary metric cards (Subdomains found, crt.sh count, DNS count, live hosts, open ports).
   - Machine-readable JSON output alongside the HTML report.

---

## Roadmap

- [x] Add certificate transparency log lookup (crt.sh) as an additional subdomain source
- [x] Multi-target support (CIDR ranges, target lists)
- [x] Automated HTTP title and web service probing
- [x] JSON and CSV reporting for `port_scanner.py`
- [x] Interactive real-time search & filtering in HTML recon reports
- [ ] Multi-target CIDR expansion in automated nmap pipeline
- [ ] Screenshot web ports automatically (e.g. via headless Chrome)
- [ ] Export findings directly to a ticketing system / Slack webhook

---

## Changelog

### v0.2 (5-9-2026)

- **`recon_scanner.py`**:
  - **Certificate Transparency (`crt.sh`) Integration**: Queries public CT logs via `crt.sh` JSON API for passive subdomain discovery.
  - **New CLI Flags**: Added `--crt-only` (passive OSINT mode without active brute-forcing) and `--no-crt` (DNS brute-force only).
  - **Automated Web Probing**: Automatically probes discovered web ports (80, 443, 8080, 8443, etc.) to capture HTTP status codes, page titles (`<title>`), and server headers.
  - **Multi-Target & CIDR Support**: Added support for comma-separated targets, CIDR ranges, and target files (`-iL / --target-list`).
  - **Interactive Dark-Mode Dashboard**: Redesigned HTML report with real-time client-side search/filtering, source badges (`crt.sh` vs `DNS Brute-force`), and summary metric cards.

- **`port_scanner.py`**:
  - **Multi-Target & CIDR Support**: Scan individual hosts, comma-separated lists, CIDR blocks (e.g. `192.168.1.0/28`), or target files (`-iL / --target-list`).
  - **Top-Ports Presets**: Added `--top-ports 20` and `--top-ports 100` options for high-speed common port discovery.
  - **Enhanced Banner Grabbing**:
    - Automatic banner capture for greeting protocols (SSH, FTP, SMTP, MySQL).
    - HTTP `HEAD` probing for web ports to extract `Server:` headers.
    - TLS/SSL handshake negotiation for secure ports (HTTPS, IMAPS, SMTPS) to inspect TLS status and servers.
  - **Structured Exports**: Added JSON (`-oJ / --json`) and CSV (`-oC / --csv`) export options.
  - **Expanded Services**: Expanded built-in port-to-service mapping dictionary to 100+ standard ports.

---

## License

MIT — see [LICENSE](LICENSE) for details.
