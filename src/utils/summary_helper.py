import re

def generate_summary(log_lines):
    """
    Analyzes the list of log lines and returns a formatted summary string.
    """
    hosts = set()
    open_ports = []
    os_detected = set()
    security_warnings = []

    # Regex patterns to find specific data
    host_pattern = re.compile(r"Host:\s+([\d\.]+)")
    port_pattern = re.compile(r"Port\s+(\d+)")
    os_pattern = re.compile(r"OS:\s+(.+)")

    for line in log_lines:
        # 1. Find IP Addresses
        if "Host:" in line and "State" not in line and "Hostname" not in line:
            match = host_pattern.search(line)
            if match:
                hosts.add(match.group(1))

        # 2. Find Open Ports and Services
        if "open" in line.lower() and "Port" in line:
            match = port_pattern.search(line)
            if match:
                port_num = match.group(1)
                
                # Extract service name (e.g., HTTP, SSH)
                service_match = re.search(r"-> (.+?) \(", line)
                service = service_match.group(1) if service_match else "Unknown"
                
                open_ports.append(f"Port {port_num} ({service})")

                # Check for insecure services
                if "telnet" in service.lower() or "ftp" in service.lower():
                    security_warnings.append(f"⚠️ Insecure Protocol: {service} on {port_num}")

        # 3. Find Operating Systems
        if "OS:" in line:
            match = os_pattern.search(line)
            if match:
                os_detected.add(match.group(1).strip())

    # Build the Summary Report
    report_lines = []
    report_lines.append("📊 SCAN SUMMARY REPORT")
    report_lines.append("=" * 35)
    report_lines.append(f"Total Hosts Scanned: {len(hosts)}")
    
    if hosts:
        report_lines.append(f"IPs Found: {', '.join(list(hosts)[:5])}") # Show max 5 IPs
    
    report_lines.append("-" * 35)
    report_lines.append(f"Total Open Ports: {len(open_ports)}")
    
    if open_ports:
        report_lines.append("Top Ports Found:")
        # Show top 5 ports found
        for p in open_ports[:5]:
            report_lines.append(f"  • {p}")
    
    report_lines.append("-" * 35)
    report_lines.append("Operating Systems:")
    if os_detected:
        for os_name in os_detected:
            report_lines.append(f"  • {os_name}")
    else:
        report_lines.append("  • Unknown (Firewall likely blocking OS detection)")

    if security_warnings:
        report_lines.append("-" * 35)
        report_lines.append("⚠️ SECURITY ALERTS:")
        for warn in security_warnings:
            report_lines.append(f"  {warn}")

    return "\n".join(report_lines)