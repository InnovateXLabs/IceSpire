import socket
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

def ice_resolve_target(target):
    """
    Converts a hostname or URL to an IP address (supports IPv4 and IPv6).
    """
    try:
        # If the input is a URL, extract the hostname
        if "://" in target:
            parsed_url = urlparse(target)
            target = parsed_url.hostname

        # Resolve the hostname to an IP address (supports IPv4 and IPv6)
        addr_info = socket.getaddrinfo(target, None)
        ip = addr_info[0][4][0]  # Get the first resolved IP address
        print(f"[+] IceSpire: Resolved {target} to IP: {ip}")
        return ip
    except (socket.gaierror, IndexError):
        print(f"[-] IceSpire: Failed to resolve {target} to an IP. Ensure the hostname/URL is valid.")
        return None

def ice_validate_ip(ip):
    """
    Checks if a string is a valid IPv4 or IPv6 address.
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def ice_scan_port(ip, port):
    """
    Scans a specific port on the target IP and detects the service running on it.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            print(f"[!] IceSpire: Port {port} is open on {ip} (Service: {service})")
            return port, service
        else:
            print(f"[ ] IceSpire: Port {port} is closed on {ip}")
            return None
    except Exception as e:
        print(f"[-] IceSpire: Error scanning port {port}: {e}")
        return None
    finally:
        sock.close()

def ice_generate_report(ip, open_ports):
    """
    Generates a JSON report of the scan results.
    """
    report = {
        "target_ip": ip,
        "open_ports": open_ports
    }
    with open("icespire_scan_report.json", "w") as report_file:
        json.dump(report, report_file, indent=4)
    print(f"[+] IceSpire: Scan report saved to 'icespire_scan_report.json'.")

def ice_main():
    """
    Main function for the IceSpire Scanner.
    """
    print("""
    ╔══════════════════════════════════════════════════╗
    ║                IceSpire Scanner                 ║
    ║  A simple tool for scanning network targets     ║
    ╚══════════════════════════════════════════════════╝
    """)

    # Prompt the user for a target input
    target = input("Enter target (IP/hostname/URL): ").strip()

    # If the input is already an IP, use it directly
    if ice_validate_ip(target):
        print(f"[+] IceSpire: Input is a valid IP address: {target}")
        ip = target
    else:
        # If it's not an IP, resolve it to an IP
        ip = ice_resolve_target(target)
        if not ip:
            return  # Exit if resolution fails

    # Perform port scanning with multithreading
    print(f"\n[+] IceSpire: Scanning target IP: {ip}")
    ports_to_scan = [21, 22, 80, 443, 8080, 3306, 3389]  # List of ports to scan
    open_ports = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(lambda port: ice_scan_port(ip, port), ports_to_scan)
        for result in results:
            if result:
                open_ports.append({"port": result[0], "service": result[1]})

    # Generate a report
    if open_ports:
        ice_generate_report(ip, open_ports)
    else:
        print("[+] IceSpire: No open ports found.")

    print("\n[+] IceSpire: Scanning complete.")

if __name__ == "__main__":
    ice_main()