# Phishing_Detector
Phishing URL Scanner &amp; Threat Analyzer - Detect phishing, malware, and scam URLs using multiple OSINT databases and heuristics analysis.


# 🛡️ Phishing Detector - URL Scanner

A powerful phishing URL detection tool that analyzes URLs using multiple OSINT databases, heuristic analysis, and threat intelligence sources to identify phishing, malware, and scam attempts.

## Features

- **Multi-Source Scanning** - Checks URL against URLhaus, urlscan.io, and ScanMyLinks
- **Heuristic Analysis** - Detects suspicious TLDs, IP-based URLs, URL shorteners, missing HTTPS
- **Page Content Analysis** - Scans for login forms, phishing keywords, hidden elements, external scripts
- **Risk Scoring** - 0-100 risk score with threat classification (PHISHING, MALWARE, SCAM, SUSPICIOUS)
- **URL Hashing** - Generates MD5, SHA1, SHA256 hashes for the URL
- **Branded Banner** - ASCII art banner with social links
- **Color-coded Output** - Red, Blue, Green, Purple ANSI colors only

## Installation

```bash
git clone https://github.com/MoazMohamed891/phishing-detector.git
cd phishing-detector
pip install requests beautifulsoup4
python phishing_detector.py <url>

python phishing_detector.py http://example.com
python phishing_detector.py https://suspicious-site.xyz/login
python phishing_detector.py http://192.168.1.1/phishing
