from scanner.nmap_scanner import scan_ports
from scanner.zap_scanner import zap_scan
from scanner.whois_lookup import whois_lookup, dns_lookup, ipinfo_lookup, abuseipdb_lookup
from reports.report_generator import generate_pdf_report, generate_csv_report
from dotenv import load_dotenv
import time
import os

def main():
    """
    CLI entry point for HackGuard.
    1. Loads environment variables (for ZAP_API_KEY).
    2. Asks for a target domain/IP.
    3. Runs all scans and generates reports.
    """
    start_time = time.time()
    load_dotenv() 
    zap_api_key = os.getenv("ZAP_API_KEY", "")
    ipinfo_api_key = os.getenv("IPINFO_API_KEY", "")
    abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")

    target = input("Enter target (IP or domain): ")

    print("[*] Running Port Scan...")
    ports = scan_ports(target)

    print("[*] Running Web Security Scan...")
    zap_results = zap_scan(target, api_key=zap_api_key)

    print("[*] Running WHOIS Lookup...")
    whois_data = whois_lookup(target)

    print("[*] Running DNS Lookup...")
    dns_data = dns_lookup(target)

    ip_address = dns_data[0] if isinstance(dns_data, list) and dns_data else None

    if ip_address:
        print("[*] Running IPinfo Lookup...")
        ipinfo_data = ipinfo_lookup(ip_address, api_key=ipinfo_api_key)

        print("[*] Running AbuseIPDB Lookup...")
        abuseipdb_data = abuseipdb_lookup(ip_address, api_key=abuseipdb_api_key)
    else:
        ipinfo_data = {"error": "Could not resolve domain to IP"}
        abuseipdb_data = {"error": "Could not resolve domain to IP"}

    # Aggregate results
    scan_results = {
        "Ports": ports,
        "Vulnerabilities": zap_results,
        "Whois": whois_data,
        "DNS": dns_data,
        "IPinfo": ipinfo_data,
        "AbuseIPDB": abuseipdb_data
    }

    print("\n[+] Scan Completed!")
    print(scan_results)

    final_data = [
        f"Ports: {ports}",
        f"Vulnerabilities: {zap_results}",
        f"WHOIS: {whois_data}",
        f"DNS: {dns_data}",
    ]
    generate_csv_report("HackGuard_Report.csv", final_data)
    generate_pdf_report(final_data, output_path="HackGuard_Report.pdf")

    print(f"\n[+] Report Generated in {round(time.time() - start_time, 2)} seconds")


if __name__ == "__main__":
    main()
