# HackGuard - Automated Security Scanner

HackGuard is a Python-based automated web security scanner designed for ethical hacking, penetration testing, and educational purposes. It scans websites, APIs, and local web apps for vulnerabilities like SQL Injection, XSS, CSRF, and open ports. The tool leverages OWASP ZAP, Nmap, and DNS/WHOIS lookups.

## Features

* Automated OWASP ZAP Vulnerability Scan (SQLi, XSS, CSRF, etc.)
* Port Scanning with Nmap
* DNS and WHOIS Lookup
* Generates PDF and CSV Security Reports
* CLI Interface
* IP reputation check (Optional with AbuseIPDB/IPInfo)

## Tech Stack

* Python 3
* OWASP ZAP API
* Nmap
* DNS Python
* Python-WHOIS
* ReportLab (PDF Generation)
* SQLite (Optional for logging)
* dotenv (for API key management)

## Installation

1. **Clone the repository**

```
git clone https://github.com/LalwaniPalash/HackGuard.git
cd HackGuard
```

2. **Install dependencies**

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. **Install Nmap**

```
sudo apt install nmap  # Linux
brew install nmap      # macOS
```

4. **Install OWASP ZAP (Locally)**
    * Download ZAP from: https://www.zaproxy.org/download/
    * Run ZAP:

        ```
        ./zap.sh  # Linux/macOS
        zap.bat   # Windows
        ```

## Getting ZAP API Key

1. Open ZAP GUI
2. Go to `Tools` → `Options` → `API`
3. **Enable API**
4. Set or copy the API key (default port is `localhost:8080`)
5. Add your API key to a `.env` file:

```
ZAP_API_KEY=your_zap_api_key
```

## Running the Tool

```
python hackguard.py
```

You'll be prompted to enter a target URL (e.g., `http://testphp.vulnweb.com`).

## Output

* `HackGuard_Report.pdf` \- Detailed PDF report with vulnerabilities\, ports\, and DNS info
* `HackGuard_Report.csv` \- CSV format report

## Example Test Targets (Ethical Only)

* http://testphp.vulnweb.com
* http://zero.webappsecurity.com
* http://scanme.nmap.org (For port scan only)

## License

This project is licensed under the [The Unlicense](https://unlicense.org/).

## Disclaimer

* For **educational purposes only**.
* Do **NOT scan websites without permission**.
* Use only on **legal targets** or within authorized environments.

## Contributions

Pull requests are welcome! Feel free to fork the repository and submit improvements.