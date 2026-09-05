import argparse
import csv
import ipaddress
import json
import queue
import socket
import ssl
import sys
import threading
import time
from datetime import datetime
COMMON_PORTS = {
    7: "Echo", 20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    43: "WHOIS", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 79: "Finger",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind", 119: "NNTP",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 194: "IRC",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE",
    514: "Syslog", 515: "LPD", 520: "RIP", 587: "SMTP-Submission", 631: "IPP",
    636: "LDAPS", 873: "rsync", 902: "VMware", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1434: "MSSQL-UDP",
    1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL", 2181: "ZooKeeper",
    2222: "DirectAdmin/SSH", 2375: "Docker", 2376: "Docker-SSL", 3000: "Node/Dev",
    3128: "Squid", 3306: "MySQL", 3389: "RDP", 4369: "Erlang-EPMD",
    5000: "Flask/Docker-Reg", 5060: "SIP", 5222: "XMPP", 5432: "PostgreSQL",
    5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6000: "X11", 6379: "Redis", 6443: "Kubernetes-API",
    6667: "IRC", 7001: "WebLogic", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter/HTTP-Alt",
    9000: "SonarQube/PHP", 9090: "Prometheus", 9092: "Kafka", 9100: "Node-Exporter",
    9200: "Elasticsearch", 9418: "Git", 9999: "UrBackup", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-Shard",
    28017: "MongoDB-Web", 50000: "SAP", 50070: "Hadoop-HDFS"
}
TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636,
    873, 902, 990, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883,
    2049, 2082, 2083, 2086, 2087, 2181, 2222, 3000, 3128, 3306, 3389, 4369,
    5000, 5060, 5222, 5432, 5672, 5900, 5984, 5985, 6000, 6379, 7001, 8000,
    8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9092, 9100, 9200, 9418,
    9999, 10000, 11211, 27017, 27018, 28017, 50000, 50070
]

TLS_PORTS = {443, 8443, 993, 995, 465, 636, 2083, 2087, 2376, 5986, 6443}
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9000}


def parse_ports(port_arg):
    """Parse port string like '80', '1-1024', or '22,80,443'."""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start.strip()), int(end.strip())
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


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


def grab_tls_banner(target_ip, port, timeout=1.5):
    """Attempt TLS handshake and extract server header or cert info."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_ip) as ssock:
                try:
                    ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nConnection: close\r\n\r\n")
                    data = ssock.recv(1024).decode(errors="ignore")
                    for line in data.splitlines():
                        if line.lower().startswith("server:"):
                            return f"TLS: {line.strip()[:80]}"
                    first_line = data.strip().splitlines()
                    if first_line:
                        return f"TLS: {first_line[0][:80]}"
                except Exception:
                    pass
                return "TLS Handshake OK"
    except Exception:
        return ""


def grab_banner(sock, target_ip, port, timeout=1.0):
    """Enhanced banner grabbing: socket greeting, HTTP probe, or TLS handshake."""
    if port in TLS_PORTS:
        tls_res = grab_tls_banner(target_ip, port, timeout=max(timeout, 1.5))
        if tls_res:
            return tls_res

    try:
        sock.settimeout(timeout)
        try:
            banner = sock.recv(1024)
            if banner:
                return banner.decode(errors="ignore").strip().split("\n")[0][:80]
        except (socket.timeout, socket.error):
            pass

        if port in HTTP_PORTS:
            probe = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: ReconToolkit\r\nConnection: close\r\n\r\n".encode()
            sock.sendall(probe)
            data = sock.recv(1024).decode(errors="ignore").strip()
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.strip()[:80]
            first_line = data.splitlines()
            if first_line:
                return first_line[0][:80]

        sock.sendall(b"\r\n\r\n")
        banner = sock.recv(1024)
        if banner:
            return banner.decode(errors="ignore").strip().split("\n")[0][:80]
    except Exception:
        pass
    return ""


def scan_port(target_ip, port, timeout, grab_banners):
    """Scan a single TCP port using full connect and return result dict if open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            banner = grab_banner(sock, target_ip, port, timeout) if grab_banners else ""
            return {"port": port, "service": service, "banner": banner}
    except socket.error:
        pass
    finally:
        sock.close()
    return None


def worker(target_ip, port_queue, timeout, grab_banners, open_ports, print_lock):
    """Thread pool worker to consume ports from the queue."""
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        res = scan_port(target_ip, port, timeout, grab_banners)
        if res:
            with print_lock:
                open_ports.append(res)
                banner_str = f"  ({res['banner']})" if res["banner"] else ""
                print(f"[+] {res['port']:>5}/tcp  open   {res['service']:<14}{banner_str}")
        port_queue.task_done()


def scan_host(target, ports, threads=100, timeout=1.0, grab_banners=True):
    """Execute scan against a single host."""
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {target}")
        return None

    print("-" * 60)
    print(f"  Target:      {target} ({target_ip})")
    print(f"  Ports:       {len(ports)} port(s)")
    print(f"  Threads:     {threads}")
    print(f"  Started at:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    start = time.time()
    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    open_ports = []
    print_lock = threading.Lock()
    num_threads = min(threads, len(ports)) or 1

    worker_threads = []
    for _ in range(num_threads):
        t = threading.Thread(
            target=worker,
            args=(target_ip, port_queue, timeout, grab_banners, open_ports, print_lock),
            daemon=True,
        )
        t.start()
        worker_threads.append(t)

    for t in worker_threads:
        t.join()

    open_ports.sort(key=lambda x: x["port"])
    elapsed = time.time() - start

    if open_ports:
        print(f"[*] Found {len(open_ports)} open port(s) on {target} in {elapsed:.2f}s")
    else:
        print(f"[*] No open ports found on {target} in {elapsed:.2f}s")

    return {
        "target": target,
        "ip": target_ip,
        "open_ports": open_ports,
        "elapsed_seconds": round(elapsed, 2)
    }


def export_json(scan_results, filepath):
    """Export scan results to a formatted JSON file."""
    with open(filepath, "w") as f:
        json.dump(scan_results, f, indent=2)
    print(f"[+] JSON report saved to: {filepath}")


def export_csv(scan_results, filepath):
    """Export scan results to a CSV file."""
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "IP", "Port", "Protocol", "Service", "Banner"])
        for host in scan_results.get("hosts", []):
            for p in host.get("open_ports", []):
                writer.writerow([
                    host["target"],
                    host["ip"],
                    p["port"],
                    "tcp",
                    p["service"],
                    p["banner"]
                ])
    print(f"[+] CSV report saved to: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced TCP connect-scan port scanner with multi-target, top-ports, and JSON/CSV export."
    )
    parser.add_argument(
        "-t", "--target",
        help="Target IP address, hostname, CIDR (e.g. 192.168.1.0/29), or comma-separated list"
    )
    parser.add_argument(
        "-iL", "--target-list",
        help="Path to file containing targets to scan (one per line)"
    )
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan: '80', '1-1024', or '22,80,443' (default: 1-1024 unless --top-ports is used)"
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        choices=[20, 100],
        help="Scan top N common ports (20 or 100)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of worker threads per host (default: 100)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-connection timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable banner grabbing"
    )
    parser.add_argument(
        "-oJ", "--json",
        help="Export results to JSON file"
    )
    parser.add_argument(
        "-oC", "--csv",
        help="Export results to CSV file"
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

    if args.top_ports:
        if args.top_ports == 20:
            ports = TOP_100_PORTS[:20]
        else:
            ports = TOP_100_PORTS
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as e:
            print(f"[!] {e}")
            sys.exit(1)
    else:
        ports = list(range(1, 1025))

    print("=" * 60)
    print(f"  Recon Toolkit - Port Scanner")
    print(f"  Targets:     {len(targets)} target(s)")
    print(f"  Ports/host:  {len(ports)}")
    print(f"  Banner Grab: {'Disabled' if args.no_banner else 'Enabled'}")
    print(f"  Timestamp:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    overall_start = time.time()
    results = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets": len(targets),
        "hosts": []
    }

    try:
        for target in targets:
            host_result = scan_host(
                target=target,
                ports=ports,
                threads=args.threads,
                timeout=args.timeout,
                grab_banners=not args.no_banner
            )
            if host_result:
                results["hosts"].append(host_result)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Processing collected results...")

    overall_elapsed = time.time() - overall_start
    results["duration_seconds"] = round(overall_elapsed, 2)

    total_open = sum(len(h["open_ports"]) for h in results["hosts"])
    print("=" * 60)
    print(f"[*] All scans complete: {total_open} total open port(s) across {len(results['hosts'])} host(s) in {overall_elapsed:.2f}s")
    print("=" * 60)

    if args.json:
        export_json(results, args.json)
    if args.csv:
        export_csv(results, args.csv)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
