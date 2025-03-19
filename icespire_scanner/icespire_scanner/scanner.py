import socket
import json
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ======================== Core Scanner Functions ========================

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

def ice_generate_report(ip, open_ports, missing_headers=None, vulnerabilities=None):
    """
    Generates a JSON report of the scan results.
    """
    report = {
        "target_ip": ip,
        "open_ports": open_ports,
        "missing_security_headers": missing_headers if missing_headers else [],
        "vulnerabilities": vulnerabilities if vulnerabilities else []
    }
    with open("icespire_scan_report.json", "w") as report_file:
        json.dump(report, report_file, indent=4)
    print(f"[+] IceSpire: Scan report saved to 'icespire_scan_report.json'.")

# ======================== Additional Security Analysis Functions ========================

def ice_check_http_headers(url):
    """
    Checks for missing security headers in the HTTP response.
    """
    try:
        response = requests.get(url)
        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]

        missing_headers = [header for header in security_headers if header not in headers]
        if missing_headers:
            print(f"[-] IceSpire: Missing security headers: {', '.join(missing_headers)}")
        else:
            print("[+] IceSpire: All security headers are present.")
        return missing_headers
    except Exception as e:
        print(f"[-] IceSpire: Error checking HTTP headers: {e}")
        return None

def ice_check_ssl_tls(domain):
    """
    Checks SSL/TLS configuration for common vulnerabilities.
    """
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"[+] IceSpire: SSL/TLS certificate is valid for {domain}.")
                return True
    except ssl.SSLError as e:
        print(f"[-] IceSpire: SSL/TLS error: {e}")
        return False

def ice_check_sensitive_files(url):
    """
    Checks for common sensitive files exposed on the target.
    """
    sensitive_files = [
        "robots.txt",
        ".htaccess",
        "wp-config.php",
        "web.config"
    ]
    found_files = []
    for file in sensitive_files:
        try:
            response = requests.get(f"{url}/{file}")
            if response.status_code == 200:
                print(f"[!] IceSpire: Sensitive file found: {file}")
                found_files.append(file)
        except Exception as e:
            print(f"[-] IceSpire: Error checking {file}: {e}")
    return found_files

# ======================== Main Function ========================

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

    # Perform additional security analysis
    missing_headers = []
    vulnerabilities = []

    if 80 in [port["port"] for port in open_ports]:
        missing_headers = ice_check_http_headers(f"http://{ip}")
    if 443 in [port["port"] for port in open_ports]:
        missing_headers = ice_check_http_headers(f"https://{ip}")
        ice_check_ssl_tls(ip)

    if 80 in [port["port"] for port in open_ports] or 443 in [port["port"] for port in open_ports]:
        vulnerabilities = ice_check_sensitive_files(f"http://{ip}")

    # Generate a report
    if open_ports:
        ice_generate_report(ip, open_ports, missing_headers, vulnerabilities)
    else:
        print("[+] IceSpire: No open ports found.")

    print("\n[+] IceSpire: Scanning complete.")

if __name__ == "__main__":
    ice_main()