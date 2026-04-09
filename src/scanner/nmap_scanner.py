import nmap
import socket

# Common port mapping for quick reference
PORT_INFO = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-Proxy"
}

def check_nmap_installed():
    """Check if nmap is available on the system."""
    try:
        scanner = nmap.PortScanner()
        return True
    except Exception:
        return False

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def discover_hosts(network_range):
    """Scan the network to find live hosts (Ping Scan)."""
    scanner = nmap.PortScanner()
    devices = []
    
    try:
        # -sn: Ping scan, -T4: Speed, --disable-arp-ping: (Optional, depends on need)
        # Keeping original logic: -sn -PS -PA -PU -T4 -n
        scanner.scan(hosts=network_range, arguments="-sn -PS -PA -PU -T4 -n")
        
        for host in scanner.all_hosts():
            hostname = scanner[host].hostname() or "Unknown"
            state = scanner[host].state()
            devices.append({
                "ip": host,
                "hostname": hostname,
                "state": state
            })
    except Exception as e:
        return [f"Error discovering hosts: {e}"]
        
    return devices

def run_scan(target_ip, port_range, scan_type):
    """Perform a detailed scan on a specific target."""
    scanner = nmap.PortScanner()
    results = []

    try:
        arguments = ""
        
        # Construct arguments based on scan type
        if scan_type == "Quick Scan":
            arguments = "-F -T4 --open -n"
        elif scan_type == "Full Scan":
            arguments = "-p- -T4 --open -n"
        elif scan_type == "Service Detection":
            # Use provided port range, or default top 1000 if empty
            ports = port_range if port_range else "1-1000"
            arguments = f"-sV -T4 -n --open -p {ports}"
        elif scan_type == "Host Discovery":
            arguments = "-sn -T4 -n"
        elif scan_type == "Aggressive Scan":
            arguments = "-A -T4 -n"
        elif scan_type == "UDP Scan":
            arguments = "-sU -T4 -n --top-ports 100" # Limited top ports for UDP speed
        elif scan_type == "Stealth Scan":
            arguments = "-sS -T4 -n --open"
        else:
            arguments = "-F -T4"

        scanner.scan(target_ip, arguments=arguments)

        if not scanner.all_hosts():
            return ["No hosts found or target is offline."]

        for host in scanner.all_hosts():
            results.append("=" * 40)
            results.append(f"Host: {host} ({scanner[host].state()})")
            
            hostname = scanner[host].hostname() or get_hostname(host)
            if hostname:
                results.append(f"Hostname: {hostname}")

            # MAC Address & Vendor
            if 'mac' in scanner[host]['addresses']:
                mac = scanner[host]['addresses']['mac']
                results.append(f"MAC: {mac}")
                # Vendor logic
                if 'vendor' in scanner[host] and mac in scanner[host]['vendor']:
                    results.append(f"Vendor: {scanner[host]['vendor'][mac]}")

            # OS Detection
            if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                os_name = scanner[host]['osmatch'][0]['name']
                results.append(f"OS: {os_name}")

            results.append("-" * 20)
            results.append("PORTS")

            if scan_type != "Host Discovery":
                ports_found = False
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        port_data = scanner[host][proto][port]
                        if port_data['state'] == 'open':
                            ports_found = True
                            service = port_data['name']
                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            extrainfo = port_data.get('extrainfo', '')
                            
                            # Description from our map or 'Unknown'
                            desc = PORT_INFO.get(port, "Unknown")
                            
                            detail_str = f"{service.upper()} ({desc})"
                            if product:
                                detail_str += f" | {product}"
                            if version:
                                detail_str += f" {version}"
                            
                            results.append(f"Port {port:>5}/{proto} | {detail_str}")

                if not ports_found:
                    results.append("No open ports found on this host.")
            
            results.append("=" * 40 + "\n")

        return results

    except Exception as e:
        return [f"Scanning Error: {e}"]