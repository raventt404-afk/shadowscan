import socket

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
}

def scan_ports(ip: str, timeout=0.5):
    results = []

    if not ip:
        return results

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                results.append({
                    "port": port,
                    "service": service,
                    "risk": "HIGH" if port in [21, 23, 445, 3389] else "MEDIUM"
                })
            sock.close()
        except:
            pass

    return results
