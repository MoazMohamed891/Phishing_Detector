# 🛡️ Phishing Detector - URL Scanner & Threat Analyzer

A powerful phishing URL detection tool that analyzes URLs using multiple OSINT databases, heuristic analysis, and threat intelligence sources to identify phishing, malware, and scam attempts.

---

## 🚀 Features

### 🔍 Multi-Source Threat Detection

Checks URLs against multiple threat intelligence sources:

* URLhaus (abuse.ch)
* urlscan.io
* ScanMyLinks

### 🧠 Heuristic Analysis

Detects suspicious indicators such as:

* IP-based URLs
* Suspicious TLDs (.xyz, .tk, .top, .buzz, etc.)
* URL shorteners (bit.ly, tinyurl, goo.gl, etc.)
* Missing HTTPS encryption

### 🌐 Web Page Analysis

Analyzes page content for phishing behavior:

* Login forms & password fields
* Phishing-related keywords
* Hidden elements
* External scripts and resources

### 📊 Risk Scoring System

Generates a risk score from **0–100** and classifies threats as:

* 🚨 PHISHING
* ☠️ MALWARE
* ⚠️ SCAM
* 🔍 SUSPICIOUS

### 🔐 URL Hash Generation

Automatically generates:

* MD5
* SHA1
* SHA256

### 🎨 User-Friendly Interface

* ASCII Art Banner
* Colorized Terminal Output
* Clean & Structured Results

---

## 📦 Installation

```bash
git clone https://github.com/MoazMohamed891/phishing-detector.git
cd phishing-detector

pip install requests beautifulsoup4
```

---

## ▶️ Usage

```bash
python phishing_detector.py <url>
```

### Examples

```bash
python phishing_detector.py http://example.com

python phishing_detector.py https://suspicious-site.xyz/login

python phishing_detector.py http://192.168.1.1/phishing
```

---

## 🔎 What the Scanner Checks

| Check             | Description                                |
| ----------------- | ------------------------------------------ |
| HTTPS             | Verifies secure encrypted connection       |
| IP Address        | Detects raw IP-based URLs                  |
| Suspicious TLD    | Flags potentially risky domains            |
| URL Shorteners    | Detects shortened URLs                     |
| Trusted Domain    | Compares against known legitimate domains  |
| Login Forms       | Finds password and authentication forms    |
| Phishing Keywords | Searches for common phishing terms         |
| External Scripts  | Counts scripts loaded from other domains   |
| Hidden Elements   | Detects hidden content and suspicious HTML |

---

## 🌍 External Intelligence Sources

### URLhaus

Community-driven malware and phishing database.

### urlscan.io

Website scanning and threat intelligence platform.

### ScanMyLinks

Online URL safety verification service.

---

## 📈 Risk Levels

| Score    | Risk Level     | Recommendation          |
| -------- | -------------- | ----------------------- |
| 60 - 100 | 🚨 HIGH RISK   | Do NOT visit this URL   |
| 30 - 59  | ⚠️ MEDIUM RISK | Proceed with caution    |
| 0 - 29   | ✅ LOW RISK     | Appears relatively safe |

---

## 📸 Sample Output

```text
================================================
URL: https://example.com

Risk Score: 72/100
Classification: PHISHING

Indicators Found:
[+] Login Form Detected
[+] Suspicious TLD
[+] External Scripts
[-] HTTPS Enabled

Recommendation:
Do NOT enter personal information.
================================================
```

---

## ⚠️ Disclaimer

This tool is intended for educational, research, and defensive cybersecurity purposes only.

The results are based on publicly available intelligence sources and heuristic analysis and should not be considered a guarantee of maliciousness or safety.

---

## 👨‍💻 Author

**Moaz Mohamed**

* GitHub: @MoazMohamed891
* LinkedIn: Moaz Mohamed

⭐ If you find this project useful, consider giving it a star on GitHub.

