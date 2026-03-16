import nmap

def run_scan(target_ip, port_range):
    scanner = nmap.PortScanner()

    try:
        scanner.scan(target_ip, port_range)

        result = ""

        for host in scanner.all_hosts():
            result += f"Host: {host}\n"
            result += f"State: {scanner[host].state()}\n"

            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()

                for port in ports:
                    state = scanner[host][proto][port]['state']
                    result += f"Port {port}: {state}\n"

        return result

    except Exception as e:
        return f"Error: {e}"
