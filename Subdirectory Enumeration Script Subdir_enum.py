#!/usr/bin/env python3
"""
Passive Subdomain Enumeration Tool
Author: John Jeffrey Mahiban
Description: This tool passively discovers subdomains by querying public CT logs (crt.sh).
"""

import requests
import json
import sys

def fetch_subdomains(domain):
    print(f"\n[+] Gathering subdomains for: {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print("[-] Failed to retrieve data.")
            return []
        data = response.json()
        subdomains = set()
        for entry in data:
            name = entry['name_value']
            for sub in name.split('\n'):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception as e:
        print(f"[-] Error: {e}")
        return []

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 sub_enum.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    subdomains = fetch_subdomains(domain)

    if subdomains:
        print(f"\n[✔] Found {len(subdomains)} unique subdomains:\n")
        for i, sub in enumerate(subdomains, 1):
            print(f"{i}. {sub}")
    else:
        print("[-] No subdomains found or error occurred.")

if __name__ == "__main__":
    main()
