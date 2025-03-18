import ipinfo
import whoisdomain as whois
import dns.resolver
import requests

def whois_lookup(domain):
    """Fetch WHOIS data using python-whois."""
    try:
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

        w = whois.query(domain)
        return {
            "Domain": domain,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Name Servers": w.name_servers
        }
    except Exception as e:
        return {"error": str(e)}

def dns_lookup(domain):
    """Perform DNS A record lookup."""
    try:
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        answers = dns.resolver.resolve(domain, "A")
        return [ip.address for ip in answers]
    except Exception as e:
        return {"error": str(e)}

def ipinfo_lookup(ip, api_key):
    """Fetch IP details from IPinfo."""
    try:
        ipinfo_handler = ipinfo.getHandler(api_key)
        details = ipinfo_handler.getDetails(ip)
        return details.all
    except Exception as e:
        return {"error": str(e)}

def abuseipdb_lookup(ip, api_key):
    """Check if an IP is malicious using AbuseIPDB."""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        response = requests.get(url, headers=headers, params=params)
        data = response.json()

        if "data" in data:
            return data["data"]
        else:
            return {"error": "No data found"}
    except Exception as e:
        return {"error": str(e)}