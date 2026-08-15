import argparse
import concurrent.futures
import json
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# A small built-in default wordlist so the tool works out of the box.
# For real engagements, swap in something like SecLists' subdomains-top1million-5000.txt
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "api",
    "dev", "staging", "test", "vpn", "admin", "portal", "blog", "shop",
    "app", "cdn", "static", "m", "mobile", "beta", "demo", "git", "gitlab",
    "jenkins", "jira", "confluence", "docs", "support", "help", "status",
    "remote", "secure", "cloud", "db", "mysql", "sql", "dashboard", "cpanel",
]


def is_domain(target):
    try:
        socket.inet_aton(target)
        return False
    except socket.error:
        return True


def enumerate_subdomains(domain, wordlist, max_workers=50):
    found = []

    def check(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip)
        except socket.gaierror:
            return None

    print(f"[*] Brute-forcing {len(wordlist)} subdomain candidates for {domain}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(check, wordlist)
        for result in results:
            if result:
                fqdn, ip = result
                found.append({"subdomain": fqdn, "ip": ip})
                print(f"  [+] Found: {fqdn} -> {ip}")

    return found


def run_nmap(target, ports, extra_args=None):
    if not shutil.which("nmap"):
        print("[!] nmap not found in PATH. Install it with: sudo apt install nmap")
        return None

    xml_output = "/tmp/recon_scan_nmap.xml"
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

    return parse_nmap_xml(xml_output)


def parse_nmap_xml(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts_data = []

    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")

        host_entry = {"ip": ip, "ports": []}

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


def generate_html_report(report, output_path):
    subdomain_rows = "".join(
        f"<tr><td>{s['subdomain']}</td><td>{s['ip']}</td></tr>"
        for s in report.get("subdomains", [])
    )

    host_sections = ""
    for host in report.get("hosts", []):
        port_rows = "".join(
            f"<tr><td>{p['port']}/{p['protocol']}</td><td>{p['service']}</td>"
            f"<td>{p['product']} {p['version']}</td></tr>"
            for p in host["ports"]
        )
        if not port_rows:
            port_rows = "<tr><td colspan='3' class='muted'>No open ports found</td></tr>"
        host_sections += f"""
        <div class="card">
          <h3>{host['ip']}</h3>
          <table>
            <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
            <tbody>{port_rows}</tbody>
          </table>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report - {report['target']}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff; --muted: #8b949e; --open: #3fb950;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    margin: 0; padding: 40px; line-height: 1.5;
  }}
  h1 {{ color: var(--accent); margin-bottom: 4px; }}
  .meta {{ color: var(--muted); margin-bottom: 32px; font-size: 14px; }}
  h2 {{ border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 40px; }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 20px; margin-bottom: 16px;
  }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 14px; }}
  th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 12px; }}
  td:first-child {{ color: var(--open); font-family: monospace; }}
  .muted {{ color: var(--muted); font-style: italic; }}
  .badge {{
    display: inline-block; background: var(--accent); color: #0d1117;
    padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600;
  }}
</style>
</head>
<body>
  <h1>Recon Report</h1>
  <div class="meta">
    Target: <strong>{report['target']}</strong> &nbsp;|&nbsp;
    Generated: {report['timestamp']} &nbsp;|&nbsp;
    <span class="badge">{len(report.get('hosts', []))} host(s)</span>
    <span class="badge">{len(report.get('subdomains', []))} subdomain(s)</span>
  </div>

  <h2>Subdomains</h2>
  <div class="card">
    <table>
      <thead><tr><th>Subdomain</th><th>Resolved IP</th></tr></thead>
      <tbody>{subdomain_rows or "<tr><td colspan='2' class='muted'>None found / skipped</td></tr>"}</tbody>
    </table>
  </div>

  <h2>Port Scan Results</h2>
  {host_sections or "<div class='card muted'>No hosts scanned</div>"}

</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(description="Custom recon scanner: nmap + subdomain enum -> JSON/HTML report.")
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP")
    parser.add_argument("--ports", default="1-1000", help="Port range for nmap (default: 1-1000)")
    parser.add_argument("--wordlist", help="Path to a subdomain wordlist file (one per line). Uses a built-in list if omitted.")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--skip-portscan", action="store_true", help="Skip the nmap port scan")
    parser.add_argument("-o", "--output", default="recon_report", help="Output file base name (default: recon_report)")
    args = parser.parse_args()

    report = {
        "target": args.target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": [],
        "hosts": [],
    }

    scan_target = args.target
    if not args.skip_subdomains and is_domain(args.target):
        if args.wordlist:
            wordlist = [line.strip() for line in Path(args.wordlist).read_text().splitlines() if line.strip()]
        else:
            wordlist = DEFAULT_SUBDOMAINS
        report["subdomains"] = enumerate_subdomains(args.target, wordlist)
    elif not is_domain(args.target):
        print("[*] Target looks like an IP — skipping subdomain enumeration.")
    if not args.skip_portscan:
        try:
            resolved_ip = socket.gethostbyname(args.target)
        except socket.gaierror:
            print(f"[!] Could not resolve {args.target}, aborting port scan.")
            resolved_ip = None

        if resolved_ip:
            hosts = run_nmap(scan_target, args.ports)
            if hosts:
                report["hosts"] = hosts
    json_path = f"{args.output}.json"
    html_path = f"{args.output}.html"

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    generate_html_report(report, html_path)

    print("=" * 60)
    print(f"[*] JSON report:  {json_path}")
    print(f"[*] HTML report:  {html_path}")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
