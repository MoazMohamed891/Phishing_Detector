import requests
import re
import sys
import os
import time
import json
import hashlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup


RED = "\033[1;31m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
WHITE = "\033[1;37m"
RESET = "\033[0m"

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(MAGENTA + """
                                                                                         
                                                                                          
                             ,'  'KKl                                                     
                            l.   'WMMX.                                                   
                           ;:  ,ldOXWMW.                                                  
                          .0d,'..   .l0K.                                                 
                         ;K            :W.                                                
                         .k:           dc                                                 
                       'klkNk.       :0OXK0c                                              
                      ;K    .;      .'   :ckd                                             
                    ;k;                     0k:                                           
                   k0.   d::;;;;;;;;;;;,,l' .ckx'                                         
                 dXWd    d               ;.   .KM                                         
                ::;ccc;. c      ,l;      ; ..:d00c'                                       
                         '      .l'      '    ...                                         
                         .                                                                
                                                       
""" + RESET)
    print(RED + "#" * 67)
    print(RESET)
    print(BLUE + "        PHISHING DETECTOR - URL Scanner" + RESET)
    print(RED + "#" * 67)
    print(RESET)
    print(MAGENTA + " ⚡ " + BLUE + "BY.Moaz Mohamed" + MAGENTA + " ⚡" + RESET)
    print(BLUE)
    print(" Github   : https://github.com/MoazMohamed891")
    print(" Linkedin : https://www.linkedin.com/in/moaaz-mohamed-hassan-07604a348")
    print(" Website  : https://asseccccccza78184867.github.io/access/")
    print(RESET)
    print(RED + "#" * 67)
    print(RESET)
    print()

def generate_hashes(url):
    """Generate hashes for the URL"""
    hashes = {}
    hashes['MD5'] = hashlib.md5(url.encode()).hexdigest()
    hashes['SHA1'] = hashlib.sha1(url.encode()).hexdigest()
    hashes['SHA256'] = hashlib.sha256(url.encode()).hexdigest()
    return hashes

def get_url_info(url):
    """Get detailed URL information"""
    parsed = urlparse(url)
    info = {
        'scheme': parsed.scheme,
        'domain': parsed.netloc,
        'path': parsed.path,
        'query': parsed.query,
        'fragment': parsed.fragment,
        'full_url': url
    }
    return info

def check_url_shortener(url):
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 
                  'buff.ly', 'ow.ly', 'rb.gy', 'cutt.ly', 'shorturl.at']
    domain = urlparse(url).netloc.lower()
    return any(s in domain for s in shorteners)

def check_suspicious_tld(url):
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', 
                       '.club', '.work', '.buzz', '.icu', '.online', '.site']
    domain = urlparse(url).netloc.lower()
    return any(domain.endswith(tld) for tld in suspicious_tlds)

def check_ip_address(url):
    domain = urlparse(url).netloc
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(ip_pattern, domain))

def check_https(url):
    return urlparse(url).scheme == 'https'

def check_domain_age(url):
    trusted_domains = ['google.com', 'facebook.com', 'twitter.com', 'github.com',
                       'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com']
    domain = urlparse(url).netloc.lower()
    return any(trusted in domain for trusted in trusted_domains)

def analyze_page_content(url):
    indicators = []
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        login_forms = 0
        for form in forms:
            inputs = form.find_all('input', {'type': 'password'})
            if inputs:
                login_forms += 1
        
        if login_forms > 0:
            indicators.append(f"Found {login_forms} login form(s)")
        
        text = soup.get_text().lower()
        keywords = ['verify', 'account', 'suspend', 'urgent', 'confirm', 
                    'password', 'login', 'signin', 'update', 'security']
        found_keywords = [k for k in keywords if k in text]
        
        if found_keywords:
            indicators.append(f"Suspicious keywords: {', '.join(found_keywords[:5])}")
        
        scripts = soup.find_all('script', {'src': True})
        external_scripts = [s for s in scripts if urlparse(s['src']).netloc != urlparse(url).netloc]
        
        if external_scripts:
            indicators.append(f"{len(external_scripts)} external script(s)")
        
        hidden = soup.find_all(style=re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden'))
        if hidden:
            indicators.append(f"{len(hidden)} hidden element(s)")
        
  
        title = soup.find('title')
        if title:
            indicators.append(f"Page title: {title.text[:50]}")
        
    except Exception as e:
        indicators.append(f"Error: {str(e)}")
    
    return indicators

def scan_urlhaus(url):
    """Scan with URLhaus"""
    print(f"{BLUE}[*] Scanning with URLhaus...{RESET}")
    
    try:
        response = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                                data={"url": url},
                                timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "no_results":
                return {"status": "SAFE", "source": "URLhaus"}
            elif "urls" in data:
                return {"status": "MALICIOUS", "source": "URLhaus", 
                       "threat": data["urls"][0].get("threat", "unknown")}
    except:
        pass
    return None

def scan_urlscan(url):
    """Scan with urlscan.io"""
    print(f"{BLUE}[*] Scanning with urlscan.io...{RESET}")
    
    try:

        response = requests.post("https://urlscan.io/api/v1/scan/",
                                json={"url": url, "visibility": "public"},
                                timeout=10)
        if response.status_code == 200:
            data = response.json()
            result_url = data.get("result", "")
            page_url = data.get("api", "")
            

            time.sleep(3)
            
            if result_url:
                result_response = requests.get(result_url, timeout=10)
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    
                    verdicts = result_data.get("verdicts", {})
                    overall = verdicts.get("overall", {})
                    
                    malicious = overall.get("malicious", False)
                    score = overall.get("score", 0)
                    
                    page = result_data.get("page", {})
                    country = page.get("country", "Unknown")
                    server = page.get("server", "Unknown")
                    ip = page.get("ip", "Unknown")
                    
                    return {
                        "status": "MALICIOUS" if malicious else "SAFE",
                        "source": "urlscan.io",
                        "score": score,
                        "country": country,
                        "server": server,
                        "ip": ip,
                        "result_url": result_url
                    }
    except Exception as e:
        pass
    return None

def scan_scanmylinks(url):
    """Scan with scanmylinks.com"""
    print(f"{BLUE}[*] Scanning with ScanMyLinks...{RESET}")
    
    try:

        response = requests.get(f"https://www.scanmylinks.com/scan?url={url}",
                              timeout=10,
                              headers={'User-Agent': 'Mozilla/5.0'})
        
        if response.status_code == 200:

            text = response.text.lower()
            if "malicious" in text or "phishing" in text or "danger" in text:
                return {"status": "MALICIOUS", "source": "ScanMyLinks"}
            elif "safe" in text or "clean" in text:
                return {"status": "SAFE", "source": "ScanMyLinks"}
    except:
        pass

    return {"status": "UNKNOWN", "source": "ScanMyLinks", "note": "API key required for full scan"}

def get_threat_type(score, indicators):
    threat_types = []
    
    phishing_keywords = ['login', 'password', 'verify', 'account', 'signin', 'confirm']
    if any(kw in str(indicators).lower() for kw in phishing_keywords):
        threat_types.append("PHISHING")
    
    malware_indicators = ['payload', 'exploit', 'malware', 'virus', 'trojan']
    if any(ind in str(indicators).lower() for ind in malware_indicators):
        threat_types.append("MALWARE")
    
    scam_keywords = ['urgent', 'suspend', 'verify', 'confirm', 'update']
    if any(kw in str(indicators).lower() for kw in scam_keywords):
        threat_types.append("SCAM")
    
    if score >= 60:
        if "PHISHING" not in threat_types:
            threat_types.append("PHISHING")
    elif score >= 30:
        if "SCAM" not in threat_types:
            threat_types.append("SUSPICIOUS")
    
    return threat_types if threat_types else ["UNKNOWN"]

def analyze_url(url):
    print(f"\n{WHITE}[*] Analyzing: {url}{RESET}\n")
    

    hashes = generate_hashes(url)
    url_info = get_url_info(url)
    

    print(f"{WHITE}{'='*57}{RESET}")
    print(f"{WHITE}  URL INFORMATION{RESET}")
    print(f"{WHITE}{'='*57}{RESET}")
    print(f"  {BLUE}Protocol :{RESET} {url_info['scheme']}")
    print(f"  {BLUE}Domain   :{RESET} {url_info['domain']}")
    print(f"  {BLUE}Path     :{RESET} {url_info['path'] or '/'}")
    if url_info['query']:
        print(f"  {BLUE}Query    :{RESET} {url_info['query']}")
    print(f"  {BLUE}Full URL :{RESET} {url_info['full_url'][:60]}...")
    

    print(f"\n{WHITE}{'='*57}{RESET}")
    print(f"{WHITE}  URL HASHES{RESET}")
    print(f"{WHITE}{'='*57}{RESET}")
    print(f"  {MAGENTA}MD5    :{RESET} {hashes['MD5']}")
    print(f"  {MAGENTA}SHA1   :{RESET} {hashes['SHA1']}")
    print(f"  {MAGENTA}SHA256 :{RESET} {hashes['SHA256']}")
    

    score = 0
    findings = []
    
    if not check_https(url):
        score += 20
        findings.append(f"{RED}[!] No HTTPS encryption{RESET}")
    else:
        findings.append(f"{GREEN}[+] HTTPS enabled{RESET}")
    
    if check_ip_address(url):
        score += 30
        findings.append(f"{RED}[!] Uses IP address instead of domain{RESET}")
    
    if check_suspicious_tld(url):
        score += 25
        findings.append(f"{RED}[!] Suspicious TLD detected{RESET}")
    
    if check_url_shortener(url):
        score += 15
        findings.append(f"{MAGENTA}[!] Uses URL shortener{RESET}")
    
    if not check_domain_age(url):
        score += 10
        findings.append(f"{MAGENTA}[!] Unknown domain{RESET}")
    
    content_indicators = analyze_page_content(url)
    for indicator in content_indicators:
        if "suspicious" in indicator.lower() or "login" in indicator.lower():
            score += 15
            findings.append(f"{RED}[!] {indicator}{RESET}")
        else:
            findings.append(f"{MAGENTA}[!] {indicator}{RESET}")
    
    print(f"\n{WHITE}{'='*57}{RESET}")
    print(f"{WHITE}  ANALYSIS RESULTS{RESET}")
    print(f"{WHITE}{'='*57}{RESET}")
    for f in findings:
        print(f"  {f}")
    
    threat_types = get_threat_type(score, findings)
    
    print(f"\n{WHITE}{'='*57}{RESET}")
    print(f"{WHITE}  THREAT CLASSIFICATION{RESET}")
    print(f"{WHITE}{'='*57}{RESET}")
    
    for threat in threat_types:
        if threat == "PHISHING":
            print(f"  {RED}🚨 PHISHING - This is a phishing attempt!{RESET}")
        elif threat == "MALWARE":
            print(f"  {RED}🦠 MALWARE - This URL contains malware!{RESET}")
        elif threat == "SCAM":
            print(f"  {MAGENTA}⚠️  SCAM - This is a scam/fraud attempt!{RESET}")
        elif threat == "SUSPICIOUS":
            print(f"  {MAGENTA}⚠️  SUSPICIOUS - This URL shows suspicious behavior{RESET}")
        else:
            print(f"  {GREEN}❓ UNKNOWN - Further analysis needed{RESET}")
    
    print(f"\n{WHITE}{'='*57}{RESET}")
    print(f"{WHITE}  RISK ASSESSMENT{RESET}")
    print(f"{WHITE}{'='*57}{RESET}")
    
    if score >= 60:
        print(f"  {RED}[!!!] HIGH RISK - Score: {score}/100{RESET}")
        print(f"  {RED}⛔ DO NOT VISIT THIS URL!{RESET}")
    elif score >= 30:
        print(f"  {MAGENTA}[!!] MEDIUM RISK - Score: {score}/100{RESET}")
        print(f"  {MAGENTA}⚠️  BE CAREFUL WITH THIS URL{RESET}")
    else:
        print(f"  {GREEN}[+] LOW RISK - Score: {score}/100{RESET}")
        print(f"  {GREEN}✅ This URL appears to be relatively safe{RESET}")
    
    print(f"\n{WHITE}{'='*57}{RESET}")
    print(f"{WHITE}  EXTERNAL SCANS{RESET}")
    print(f"{WHITE}{'='*57}{RESET}")
    
    
    print()
    
    # 1. URLhaus
    urlhaus_result = scan_urlhaus(url)
    if urlhaus_result:
        if urlhaus_result["status"] == "MALICIOUS":
            print(f"  {RED}🚨 URLhaus: MALICIOUS - {urlhaus_result.get('threat', 'known threat')}{RESET}")
        elif urlhaus_result["status"] == "SAFE":
            print(f"  {GREEN}✅ URLhaus: SAFE{RESET}")
        else:
            print(f"  {MAGENTA}⚠️  URLhaus: {urlhaus_result.get('status', 'Unknown')}{RESET}")
    else:
        print(f"  {MAGENTA}⚠️  URLhaus: Unable to scan{RESET}")


    urlscan_result = scan_urlscan(url)
    if urlscan_result:
        if urlscan_result["status"] == "MALICIOUS":
            print(f"  {RED}🚨 urlscan.io: MALICIOUS (Score: {urlscan_result.get('score', 'N/A')}){RESET}")
            print(f"     {RED}IP: {urlscan_result.get('ip', 'N/A')} | Country: {urlscan_result.get('country', 'N/A')}{RESET}")
            if urlscan_result.get('result_url'):
                print(f"     {BLUE}Result: {urlscan_result['result_url']}{RESET}")
        elif urlscan_result["status"] == "SAFE":
            print(f"  {GREEN}✅ urlscan.io: SAFE{RESET}")
            print(f"     {GREEN}IP: {urlscan_result.get('ip', 'N/A')} | Server: {urlscan_result.get('server', 'N/A')}{RESET}")
        else:
            print(f"  {MAGENTA}⚠️  urlscan.io: {urlscan_result.get('status', 'Unknown')}{RESET}")
    else:
        print(f"  {MAGENTA}⚠️  urlscan.io: Unable to scan{RESET}")
    

    scanmylinks_result = scan_scanmylinks(url)
    if scanmylinks_result:
        if scanmylinks_result["status"] == "MALICIOUS":
            print(f"  {RED}🚨 ScanMyLinks: MALICIOUS{RESET}")
        elif scanmylinks_result["status"] == "SAFE":
            print(f"  {GREEN}✅ ScanMyLinks: SAFE{RESET}")
        else:
            print(f"  {MAGENTA}⚠️  ScanMyLinks: {scanmylinks_result.get('note', 'Unknown')}{RESET}")
    else:
        print(f"  {MAGENTA}⚠️  ScanMyLinks: Unable to scan{RESET}")
    

    print(f"\n{BLUE}[*] VirusTotal: Get free API key at https://www.virustotal.com/{RESET}")
    print(f"{BLUE}[*] ScanMyLinks: https://www.scanmylinks.com/{RESET}")
    print(f"{BLUE}[*] urlscan.io: https://urlscan.io/{RESET}")
    
    return score

def main():
    show_banner()
    
    if len(sys.argv) < 2:
        print(f"{BLUE}[*] Usage: python phishing_detector.py <url>{RESET}")
        print(f"{BLUE}[*] Example: python phishing_detector.py http://example.com{RESET}")
        print(f"{BLUE}[*] Example: python phishing_detector.py http://192.168.1.1/login{RESET}")
        return
    
    url = sys.argv[1]
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    analyze_url(url)

if __name__ == "__main__":
    main()
