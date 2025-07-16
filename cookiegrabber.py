#!/usr/bin/env python3
# Author- John Jeffrey Mahiban
# Tool - Cookiegrabber checks for cookie flags 


import requests

def check_cookies(site):
    print(f"\nChecking cookies for: {site}\n{'-'*50}")

    try:
        res = requests.get(site)
    except Exception as e:
        print(f"Error: Can't reach site - {e}")
        return

    try:
        cookies_raw = res.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw = res.headers.get("Set-Cookie", "")
        cookies_raw = [raw] if raw else []

    if not cookies_raw:
        print("No cookies found.\n")
        return

    for c in cookies_raw:
        c_low = c.lower()
        print("Cookie:")
        print(f"  {c.strip()}")
        print("Flags:")
        print(f"  HttpOnly: {'Yes' if 'httponly' in c_low else 'No'}")
        print(f"  Secure:   {'Yes' if 'secure' in c_low else 'No'}")

        if "samesite=strict" in c_low:
            ss = "Strict"
        elif "samesite=lax" in c_low:
            ss = "Lax"
        elif "samesite=none" in c_low:
            ss = "None"
        else:
            ss = "Not set"
        print(f"  SameSite: {ss}")

        domain_flag = "Shared across subs" if "domain=" in c_low else "Host-only"
        print(f"  Domain:   {domain_flag}")

        print("-"*50)

if __name__ == "__main__":
    print("Starting Cookie Flags QuickCheck")  # Debug print
    site = input("Put site URL (with https://): ").strip()
    check_cookies(site)
