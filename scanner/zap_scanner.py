import time
from zapv2 import ZAPv2

def zap_scan(target, api_key, zap_url="http://localhost:8080"):
    """
    Runs OWASP ZAP Spider, Passive Scan, and Active Scan on the given target.
    Filters out low-severity alerts.
    """
    zap = ZAPv2(apikey=api_key, proxies={"http": zap_url, "https": zap_url})

    # Spidering the target
    zap.spider.scan(target)
    while int(zap.spider.status()) < 100:
        print(f"[*] Spidering. Progress: {zap.spider.status()}%")
        time.sleep(2)

    # Passive Scan
    while int(zap.pscan.records_to_scan) > 0:
        print(f"[*] Scanning {zap.pscan.records_to_scan} remaining")
        time.sleep(2)

    # Active Scan
    zap.ascan.scan(target)
    while int(zap.ascan.status()) < 100:
        print(f"[*] Active Scanning. Progress: {zap.ascan.status()}%")
        time.sleep(5)

    # Get ZAP alerts and filter them
    all_alerts = zap.core.alerts(baseurl=target)

    # Filter only high/medium severity vulnerabilities
    filtered_alerts = [
        alert for alert in all_alerts if alert["risk"] in ["High", "Medium"]
    ]

    return filtered_alerts