import argparse
import concurrent.futures
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "api",
    "dev", "staging", "test", "vpn", "admin", "portal", "blog", "shop",
    "app", "cdn", "static", "m", "mobile", "beta", "demo", "git", "gitlab",
    "jenkins", "jira", "confluence", "docs", "support", "help", "status",
    "remote", "secure", "cloud", "db", "mysql", "sql", "dashboard", "cpanel",
    "auth", "login", "sso", "monitor", "grafana", "kibana", "gitlab", "corp"
]

WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 9000, 9443}


def is_domain(target):
    """Check if target is a hostname/domain rather than an IP address."""
    try:
        ipaddress.ip_address(target)
        return False
    except ValueError:
        return True


def expand_target(target_str):
    """Expand target string into individual host strings (handles CIDR notations)."""
    target_str = target_str.strip()
    if not target_str:
        return []
    if "/" in target_str:
        try:
            net = ipaddress.ip_network(target_str, strict=False)
            if net.num_addresses <= 2:
                return [str(ip) for ip in net]
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            pass
    return [target_str]


def parse_targets(target_arg=None, target_list_file=None):
    """Parse targets from CLI argument and/or target list file."""
    targets = []
    if target_list_file:
        try:
            with open(target_list_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.extend(expand_target(line))
        except IOError as e:
            raise ValueError(f"Could not read target list file: {e}")

    if target_arg:
        for item in target_arg.split(","):
            item = item.strip()
            if item:
                targets.extend(expand_target(item))

    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
    return unique_targets


def query_crt_sh(domain, timeout=15):
    """
    Query crt.sh Certificate Transparency logs for historical and active subdomains.
    Returns a set of discovered subdomains.
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; ReconToolkit/2.0)",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, headers=headers)
    print(f"[*] Querying Certificate Transparency logs (crt.sh) for {domain}...")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw_data = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_data)
                for item in data:
                    nv = item.get("name_value", "")
                    cn = item.get("common_name", "")
                    for entry in f"{nv}\n{cn}".splitlines():
                        entry = entry.strip().lower()
                        if entry.startswith("*."):
                            entry = entry[2:]
                        if entry.endswith(f".{domain}") or entry == domain:
                            if entry and not any(c in entry for c in ("*", " ", "@", "/", ":")):
                                subdomains.add(entry)
                print(f"  [+] crt.sh returned {len(subdomains)} unique candidate subdomain(s)")
    except urllib.error.HTTPError as e:
        print(f"  [!] crt.sh HTTP error ({e.code}): {e.reason}")
    except urllib.error.URLError as e:
        print(f"  [!] crt.sh connection error: {e.reason}")
    except json.JSONDecodeError:
        print("  [!] crt.sh returned non-JSON response.")
    except Exception as e:
        print(f"  [!] crt.sh lookup failed: {e}")

    return subdomains


def enumerate_subdomains(domain, wordlist=None, use_crt=True, crt_only=False, max_workers=50):
    """
    Enumerate subdomains via Certificate Transparency (crt.sh) and/or DNS brute-force.
    Resolves each candidate concurrently.
    """
    candidates = {}

    if use_crt:
        crt_results = query_crt_sh(domain)
        for sub in crt_results:
            candidates.setdefault(sub, set()).add("crt.sh")

    if not crt_only:
        if wordlist is None:
            wordlist = DEFAULT_SUBDOMAINS
        print(f"[*] Queueing {len(wordlist)} brute-force candidates for {domain}...")
        for sub in wordlist:
            fqdn = f"{sub}.{domain}"
            candidates.setdefault(fqdn, set()).add("DNS Brute-force")

    candidates.setdefault(domain, set()).add("Root Domain")

    print(f"[*] Resolving {len(candidates)} unique subdomain candidate(s) with {max_workers} threads...")
    found = []

    def check_subdomain(fqdn_sources):
        fqdn, sources = fqdn_sources
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip, sorted(sources))
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(check_subdomain, candidates.items())
        for r in results:
            if r:
                fqdn, ip, sources = r
                found.append({
                    "subdomain": fqdn,
                    "ip": ip,
                    "source": ", ".join(sources)
                })
                print(f"  [+] Found: {fqdn:<35} -> {ip:<16} [{', '.join(sources)}]")

    found.sort(key=lambda x: x["subdomain"])
    print(f"[*] Subdomain enumeration finished: {len(found)} active host(s) found.")
    return found


def probe_http_service(host, port, service_name="", timeout=3):
    """
    Lightweight web service probe: grabs HTTP status code, title, and server header.
    Uses pure standard library.
    """
    is_tls = port in {443, 8443, 9443, 2083, 2087} or "https" in service_name.lower() or "ssl" in service_name.lower()
    proto = "https" if is_tls else "http"
    url = f"{proto}://{host}:{port}/"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; ReconToolkit/2.0; +https://github.com/PUPPETVILLAN/recon-toolkit)",
        "Accept": "*/*"
    }
    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx if is_tls else None) as resp:
            status = resp.status
            server = resp.headers.get("Server", "")
            raw = resp.read(8192).decode("utf-8", errors="ignore")
            title_match = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip() if title_match else ""
            title = " ".join(title.split())
            return {
                "url": url,
                "status": status,
                "title": title[:100],
                "server": server[:60]
            }
    except urllib.error.HTTPError as e:
        raw = e.read(8192).decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        title_match = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else ""
        title = " ".join(title.split())
        return {
            "url": url,
            "status": e.code,
            "title": title[:100],
            "server": e.headers.get("Server", "")[:60]
        }
    except Exception:
        return None


def run_nmap(target, ports, extra_args=None):
    """Run nmap scanner and parse XML output."""
    if not shutil.which("nmap"):
        print("[!] nmap not found in PATH. Install it with: sudo apt install nmap")
        return None

    xml_output = f"/tmp/recon_scan_{int(time.time())}.xml"
    cmd = ["nmap", "-sV", "-p", ports, "-oX", xml_output, target]
    if extra_args:
        cmd.extend(extra_args)

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=1800)
    except subprocess.CalledProcessError as e:
        print(f"[!] nmap failed: {e.stderr}")
        return None
    except subprocess.TimeoutExpired:
        print("[!] nmap scan timed out.")
        return None

    try:
        hosts = parse_nmap_xml(xml_output)
        return hosts
    finally:
        if Path(xml_output).exists():
            Path(xml_output).unlink(missing_ok=True)


def parse_nmap_xml(xml_path):
    """Parse nmap XML file into structured dictionary list."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts_data = []

    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")

        hostnames = []
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                name = hn.get("name")
                if name:
                    hostnames.append(name)

        host_entry = {
            "ip": ip,
            "hostnames": hostnames,
            "ports": []
        }

        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state_elem = port.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                service_elem = port.find("service")
                host_entry["ports"].append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service_elem.get("name") if service_elem is not None else "unknown",
                    "product": service_elem.get("product", "") if service_elem is not None else "",
                    "version": service_elem.get("version", "") if service_elem is not None else "",
                })

        hosts_data.append(host_entry)

    return hosts_data


def enrich_hosts_with_web_probe(hosts_data):
    """Enrich open web ports with HTTP title, status, and server banner."""
    for host in hosts_data:
        target_host = host.get("hostnames", [host["ip"]])[0] if host.get("hostnames") else host["ip"]
        for p in host.get("ports", []):
            port_num = p["port"]
            service_name = p.get("service", "")
            if port_num in WEB_PORTS or "http" in service_name.lower():
                print(f"[*] Probing HTTP service on {target_host}:{port_num}...")
                http_info = probe_http_service(target_host, port_num, service_name=service_name)
                if http_info:
                    p["http_info"] = http_info
                    print(f"  [+] HTTP [{http_info['status']}]: {http_info['title'] or 'No Title'} (Server: {http_info['server'] or 'Unknown'})")


def generate_html_report(report, output_path):
    """Generate modern, interactive dark-mode HTML report with live search."""
    subdomains = report.get("subdomains", [])
    hosts = report.get("hosts", [])

    total_subdomains = len(subdomains)
    crt_count = sum(1 for s in subdomains if "crt.sh" in s.get("source", ""))
    dns_count = sum(1 for s in subdomains if "DNS" in s.get("source", ""))
    total_hosts = len(hosts)
    total_ports = sum(len(h.get("ports", [])) for h in hosts)

    subdomain_rows = ""
    for s in subdomains:
        src = s.get("source", "")
        badge_class = "badge-crt" if "crt.sh" in src else "badge-dns"
        subdomain_rows += f"""
        <tr class="subdomain-row" data-search="{s['subdomain']} {s['ip']} {src}">
            <td><strong>{s['subdomain']}</strong></td>
            <td><code>{s['ip']}</code></td>
            <td><span class="badge {badge_class}">{src}</span></td>
        </tr>
        """

    host_sections = ""
    for host in hosts:
        port_rows = ""
        for p in host.get("ports", []):
            version_str = f"{p['product']} {p['version']}".strip() or "—"
            http_details = ""
            search_tags = f"{p['port']} {p['protocol']} {p['service']} {version_str}"
            if "http_info" in p and p["http_info"]:
                info = p["http_info"]
                status_color = "#3fb950" if 200 <= info["status"] < 400 else "#d29922"
                title_escaped = info.get("title", "").replace("<", "&lt;").replace(">", "&gt;")
                http_details = f"""
                <div class="http-preview">
                    <span style="color: {status_color}; font-weight: bold;">[{info['status']}]</span>
                    <a href="{info['url']}" target="_blank" rel="noopener noreferrer">{title_escaped or info['url']}</a>
                    {f'<span class="server-tag">({info["server"]})</span>' if info.get('server') else ''}
                </div>
                """
                search_tags += f" {info.get('status')} {info.get('title')} {info.get('server')}"

            port_rows += f"""
            <tr class="port-row" data-search="{search_tags.lower()}">
                <td><code>{p['port']}/{p['protocol']}</code></td>
                <td><span class="service-pill">{p['service']}</span></td>
                <td>{version_str}</td>
                <td>{http_details or '<span class="muted">—</span>'}</td>
            </tr>
            """

        if not port_rows:
            port_rows = "<tr><td colspan='4' class='muted text-center'>No open ports discovered</td></tr>"

        hostname_label = f" ({', '.join(host['hostnames'])})" if host.get("hostnames") else ""
        host_sections += f"""
        <div class="card host-card" data-host="{host['ip']}">
            <div class="host-header">
                <h3>{host['ip']}{hostname_label}</h3>
                <span class="badge badge-open">{len(host.get('ports', []))} port(s) open</span>
            </div>
            <table>
                <thead>
                    <tr><th>Port</th><th>Service</th><th>Product / Version</th><th>HTTP / Banner Details</th></tr>
                </thead>
                <tbody>{port_rows}</tbody>
            </table>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report - {report['target']}</title>
<style>
  :root {{
    --bg: #0d1117;
    --card: #161b22;
    --card-hover: #1c2128;
    --border: #30363d;
    --text: #c9d1d9;
    --heading: #f0f6fc;
    --accent: #58a6ff;
    --muted: #8b949e;
    --open: #3fb950;
    --warn: #d29922;
    --purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    padding: 32px 48px; line-height: 1.5;
  }}
  header {{ margin-bottom: 24px; }}
  h1 {{ color: var(--heading); font-size: 28px; margin-bottom: 6px; }}
  h2 {{ color: var(--heading); font-size: 20px; margin: 32px 0 16px 0; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
  .meta {{ color: var(--muted); font-size: 14px; margin-bottom: 24px; }}
  .meta strong {{ color: var(--text); }}
  
  /* Stat Cards Grid */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px; margin-bottom: 24px;
  }}
  .stat-card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; text-align: center;
  }}
  .stat-num {{ font-size: 28px; font-weight: bold; color: var(--accent); }}
  .stat-label {{ font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}

  /* Search input */
  .search-container {{
    margin-bottom: 24px;
  }}
  .search-box {{
    width: 100%;
    padding: 12px 16px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-size: 15px;
    outline: none;
    transition: border-color 0.2s;
  }}
  .search-box:focus {{
    border-color: var(--accent);
  }}

  /* Cards & Tables */
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 20px; margin-bottom: 20px;
  }}
  .host-header {{
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;
  }}
  .host-header h3 {{ color: var(--heading); font-size: 18px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 14px; }}
  th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }}
  tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
  code {{ font-family: "JetBrains Mono", Consolas, monospace; color: var(--open); }}

  /* Badges & Pills */
  .badge {{
    display: inline-block; padding: 3px 10px; border-radius: 12px;
    font-size: 12px; font-weight: 600;
  }}
  .badge-crt {{ background: rgba(88, 166, 255, 0.15); color: var(--accent); border: 1px solid rgba(88, 166, 255, 0.4); }}
  .badge-dns {{ background: rgba(188, 140, 255, 0.15); color: var(--purple); border: 1px solid rgba(188, 140, 255, 0.4); }}
  .badge-open {{ background: rgba(63, 185, 80, 0.15); color: var(--open); border: 1px solid rgba(63, 185, 80, 0.4); }}
  .service-pill {{
    background: rgba(255, 255, 255, 0.06); padding: 2px 8px; border-radius: 4px; font-size: 13px;
  }}
  .http-preview {{
    display: flex; gap: 8px; align-items: center; font-size: 13px;
  }}
  .http-preview a {{ color: var(--accent); text-decoration: none; max-width: 400px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .http-preview a:hover {{ text-decoration: underline; }}
  .server-tag {{ color: var(--muted); font-size: 12px; }}
  .muted {{ color: var(--muted); font-style: italic; }}
  .text-center {{ text-align: center; }}
</style>
</head>
<body>
  <header>
    <h1>Reconnaissance Report</h1>
    <div class="meta">
      Target: <strong>{report['target']}</strong> &nbsp;|&nbsp;
      Scan Timestamp: <strong>{report['timestamp']}</strong> &nbsp;|&nbsp;
      Elapsed: <strong>{report.get('duration_seconds', 'N/A')}s</strong>
    </div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-num">{total_subdomains}</div>
      <div class="stat-label">Subdomains Discovered</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color: var(--purple);">{crt_count}</div>
      <div class="stat-label">From crt.sh</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color: var(--accent);">{dns_count}</div>
      <div class="stat-label">From DNS Brute-Force</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color: var(--open);">{total_hosts}</div>
      <div class="stat-label">Live Hosts</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color: var(--open);">{total_ports}</div>
      <div class="stat-label">Open Ports</div>
    </div>
  </div>

  <div class="search-container">
    <input type="text" id="filterInput" class="search-box" placeholder="Filter subdomains, IP addresses, ports, or services in real-time..." onkeyup="filterTables()">
  </div>

  <h2>Discovered Subdomains ({total_subdomains})</h2>
  <div class="card">
    <table id="subdomainTable">
      <thead><tr><th>Subdomain</th><th>Resolved IP</th><th>Discovery Source</th></tr></thead>
      <tbody>{subdomain_rows or "<tr><td colspan='3' class='muted text-center'>None found / skipped</td></tr>"}</tbody>
    </table>
  </div>

  <h2>Port Scan & Service Results ({total_hosts} hosts)</h2>
  <div id="hostsContainer">
    {host_sections or "<div class='card muted text-center'>No port scan data available</div>"}
  </div>

  <script>
    function filterTables() {{
      const query = document.getElementById('filterInput').value.toLowerCase().trim();

      // Filter subdomains
      const subRows = document.querySelectorAll('.subdomain-row');
      subRows.forEach(row => {{
        const text = row.getAttribute('data-search').toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
      }});

      // Filter ports inside host cards
      const hostCards = document.querySelectorAll('.host-card');
      hostCards.forEach(card => {{
        const portRows = card.querySelectorAll('.port-row');
        let cardMatches = card.getAttribute('data-host').toLowerCase().includes(query);
        let anyVisiblePort = false;

        portRows.forEach(row => {{
          const text = row.getAttribute('data-search').toLowerCase();
          if (cardMatches || text.includes(query)) {{
            row.style.display = '';
            anyVisiblePort = true;
          }} else {{
            row.style.display = 'none';
          }}
        }});

        card.style.display = (cardMatches || anyVisiblePort) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced recon automation: crt.sh + DNS brute-force + nmap service scan + HTTP probing -> JSON/HTML report."
    )
    parser.add_argument(
        "-t", "--target",
        help="Target domain, IP address, CIDR range (e.g. 192.168.1.0/29), or comma-separated list"
    )
    parser.add_argument(
        "-iL", "--target-list",
        help="Path to file containing targets (one per line)"
    )
    parser.add_argument(
        "--ports",
        default="1-1000",
        help="Port range for nmap (default: 1-1000)"
    )
    parser.add_argument(
        "--wordlist",
        help="Path to a custom subdomain wordlist file (one per line). Uses built-in list if omitted."
    )
    parser.add_argument(
        "--no-crt",
        action="store_true",
        help="Disable Certificate Transparency (crt.sh) lookup"
    )
    parser.add_argument(
        "--crt-only",
        action="store_true",
        help="Only use Certificate Transparency logs for subdomain enumeration (skip DNS brute-forcing)"
    )
    parser.add_argument(
        "--skip-subdomains",
        action="store_true",
        help="Skip subdomain enumeration entirely"
    )
    parser.add_argument(
        "--skip-portscan",
        action="store_true",
        help="Skip the nmap port scan"
    )
    parser.add_argument(
        "--skip-webprobe",
        action="store_true",
        help="Skip HTTP/HTTPS title and server probing on open web ports"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Subdomain DNS resolution thread concurrency (default: 50)"
    )
    parser.add_argument(
        "-o", "--output",
        default="recon_report",
        help="Output file base name (default: recon_report)"
    )
    args = parser.parse_args()

    if not args.target and not args.target_list:
        parser.error("You must specify a target via -t/--target or a target list via -iL/--target-list")

    try:
        targets = parse_targets(args.target, args.target_list)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    if not targets:
        print("[!] No valid targets found.")
        sys.exit(1)

    start_time = time.time()
    report = {
        "target": ", ".join(targets),
        "targets": targets,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": [],
        "hosts": [],
    }

    print("=" * 60)
    print("  Recon Toolkit - Enhanced Reconnaissance Scanner")
    print(f"  Targets:     {len(targets)} target(s)")
    print(f"  crt.sh:      {'Disabled' if args.no_crt else ('Only' if args.crt_only else 'Enabled')}")
    print(f"  Port scan:   {'Disabled' if args.skip_portscan else f'Ports {args.ports}'}")
    print(f"  Timestamp:   {report['timestamp']}")
    print("=" * 60)

    if not args.skip_subdomains:
        domain_targets = [t for t in targets if is_domain(t)]
        if domain_targets:
            wordlist = None
            if args.wordlist and not args.crt_only:
                try:
                    wordlist = [line.strip() for line in Path(args.wordlist).read_text().splitlines() if line.strip()]
                except Exception as e:
                    print(f"[!] Could not read wordlist: {e}")
                    wordlist = DEFAULT_SUBDOMAINS
            elif not args.crt_only:
                wordlist = DEFAULT_SUBDOMAINS

            for dom in domain_targets:
                sub_results = enumerate_subdomains(
                    domain=dom,
                    wordlist=wordlist,
                    use_crt=not args.no_crt,
                    crt_only=args.crt_only,
                    max_workers=args.threads
                )
                report["subdomains"].extend(sub_results)
        else:
            print("[*] No domain targets provided — skipping subdomain enumeration.")
    else:
        print("[*] Subdomain enumeration skipped.")

    if not args.skip_portscan:
        all_hosts_to_scan = []
        for t in targets:
            try:
                resolved = socket.gethostbyname(t)
                all_hosts_to_scan.append(t)
            except socket.gaierror:
                print(f"[!] Could not resolve {t}, skipping port scan.")

        for scan_target in all_hosts_to_scan:
            hosts = run_nmap(scan_target, args.ports)
            if hosts:
                if not args.skip_webprobe:
                    enrich_hosts_with_web_probe(hosts)
                report["hosts"].extend(hosts)

    report["duration_seconds"] = round(time.time() - start_time, 2)

    json_path = f"{args.output}.json"
    html_path = f"{args.output}.html"

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    generate_html_report(report, html_path)

    print("=" * 60)
    print(f"[*] Recon complete in {report['duration_seconds']}s")
    print(f"[*] JSON report:  {json_path}")
    print(f"[*] HTML report:  {html_path}")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
