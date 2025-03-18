import nmap
import re

def scan_ports(target):
    target = re.sub(r'https?://', '', target)
    nm = nmap.PortScanner()
    nm.scan(target, "75-80")
    results = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, details in nm[host][proto].items():
                results.append(f"Port: {port} | State: {details['state']}")
    
    return results

if __name__ == "__main__":
    target = input("Enter target (IP or domain): ")
    results = scan_ports(target)
    for result in results:
        print(result)