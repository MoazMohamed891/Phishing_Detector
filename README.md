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


What It Checks
Check	Description
HTTPS	Checks if URL uses encryption
IP Address	Detects raw IP usage instead of domain
Suspicious TLD	Flags .tk, .xyz, .top, .buzz and other risky TLDs
URL Shorteners	Detects bit.ly, tinyurl, goo.gl, etc.
Trusted Domain	Checks against known legitimate domains
Login Forms	Scans page for password input forms
Phishing Keywords	Detects "verify", "account", "suspend", "urgent" etc.
External Scripts	Counts scripts from different domains
Hidden Elements	Finds hidden page elements
External Scan Services
URLhaus - Abuse.ch phishing database
urlscan.io - URL scanning and verdict service
ScanMyLinks - Link safety checker
Risk Levels
HIGH RISK (60-100) - 🚨 Do NOT visit this URL
MEDIUM RISK (30-59) - ⚠️ Be careful with this URL
LOW RISK (0-29) - ✅ Appears relatively safe
Author
Moaz Mohamed

GitHub: @MoazMohamed891
LinkedIn: Moaz Mohamed
Website: Profile
