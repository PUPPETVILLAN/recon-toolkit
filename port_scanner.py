import argparse
import socket
import sys
import threading
import queue
import time
from datetime import datetime

# A small map of well-known ports -> service names, used only for display.
# This is NOT service/version detection (that requires banner grabbing or
# probing, which is a separate, heavier feature) — just a friendly label.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

print_lock = threading.Lock()
open_ports = []


def parse_ports(port_arg):
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def grab_banner(sock):
    try:
        sock.settimeout(1)
        banner = sock.recv(1024)
        if not banner:
            sock.sendall(b"\r\n")
            banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip().split("\n")[0][:80]
    except Exception:
        return ""


def scan_port(target_ip, port, timeout, grab_banners):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            banner = grab_banner(sock) if grab_banners else ""
            with print_lock:
                open_ports.append((port, service, banner))
                banner_str = f"  ({banner})" if banner else ""
                print(f"[+] {port:>5}/tcp  open   {service:<12}{banner_str}")
    except socket.error:
        pass
    finally:
        sock.close()
def worker(target_ip, port_queue, timeout, grab_banners):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        scan_port(target_ip, port, timeout, grab_banners)
        port_queue.task_done()
def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP connect-scan port scanner"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports to scan: '80', '1-1024', or '22,80,443' (default: 1-1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-connection timeout in seconds (default: 1.0)")
    parser.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {args.target}")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print("=" * 60)
    print(f"  Target:      {args.target} ({target_ip})")
    print(f"  Ports:       {len(ports)} port(s)")
    print(f"  Threads:     {args.threads}")
    print(f"  Started at:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    start = time.time()

    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    threads = []
    for _ in range(min(args.threads, len(ports)) or 1):
        t = threading.Thread(
            target=worker,
            args=(target_ip, port_queue, args.timeout, not args.no_banner),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - start
    print("=" * 60)
    if open_ports:
        print(f"[*] Scan complete: {len(open_ports)} open port(s) found in {elapsed:.2f}s")
    else:
        print(f"[*] Scan complete: no open ports found in {elapsed:.2f}s")
    print("=" * 60)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
