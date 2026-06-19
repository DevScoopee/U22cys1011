import sys
import urllib.request
from urllib.error import URLError, HTTPError

def check_security_headers(url):
    """
    Analyzes a URL to check for the presence of essential HTTP security headers.
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    print(f"[*] Analyzing security headers for: {url}\n")
    
    important_headers = {
        'Strict-Transport-Security': 'Mitigates Man-in-the-Middle attacks.',
        'Content-Security-Policy': 'Prevents Cross-Site Scripting (XSS).',
        'X-Frame-Options': 'Protects against Clickjacking.',
        'X-Content-Type-Options': 'Prevents browser MIME-sniffing.',
        'Referrer-Policy': 'Controls referrer information.'
    }

    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = response.info()
            
            missing_count = 0
            for header, description in important_headers.items():
                if header in headers:
                    print(f"[+] FOUND: {header}")
                    print(f"    Value: {headers[header]}\n")
                else:
                    print(f"[-] MISSING: {header}")
                    missing_count += 1
            
            print(f"[+] Analysis complete. Missing {missing_count} key headers.")

    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    target_url = "example.com"
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    check_security_headers(target_url)
  
