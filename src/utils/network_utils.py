import socket
import ipaddress

def get_local_ip():
    try:
        # This creates a socket but doesn't actually send data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_network_range(ip):
    try:
        # Use ipaddress module for robust CIDR calculation
        # Assuming /24 (Class C) as per your original logic
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(network)
    except Exception:
        # Fallback to original string manipulation if ipaddress fails
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ip