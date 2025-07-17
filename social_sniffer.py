#!/usr/bin/env python3
# social_sniffer.py
# Author-  John Jeffrey Mahiban
# Recon tool to check for usernames on various social media platforms

import requests
import subprocess
import json
import re
from bs4 import BeautifulSoup
from termcolor import cprint


def welcome_banner():
    print("\n" + "="*50)
    print("Social Sniffer - by rootkitdiaries.com")
    print("="*50 + "\n")


def ask_user():
    username = input("Enter the username you want to search: ").strip()
    save = input("Do you want to save the results into a JSON file? (y/n): ").strip().lower()
    output_file = None

    if save == 'y':
        output_file = input("Enter filename to save  (e.g. report.json): ").strip()
    return username, output_file


def scan_with_sherlock(username):
    cprint(f"\nSearching for {username} using Sherlock...\n", "cyan")
    try:
        result = subprocess.run(["sherlock", username, "--print-found"], capture_output=True, text=True)
    except FileNotFoundError:
        cprint("Sherlock is not installed or not found in PATH.", "red")
        return []

    links = []
    for line in result.stdout.splitlines():
        if line.startswith("[+]"):
            url = line.split(" ")[-1]
            links.append(url)
    return links


def scrape_instagram_bio(username):
    cprint(f"Checking Instagram for {username}...\n", "cyan")
    url = f"https://www.instagram.com/{username}/"
    headers = {'User-Agent': 'Mozilla/5.0'}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup.find_all("meta"):
            if tag.get("property") == "og:description":
                return tag.get("content")
        return None
    except Exception as e:
        cprint(f"Error scraping Instagram: {e}", "red")
        return None


def extract_keywords_and_emails(text):
    tech_keywords = ["cyber", "linux", "python", "docker", "nmap", "burpsuite", "autopsy", "kali", "hacking", "infosec"]
    hashtags = re.findall(r"#\w+", text.lower())
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)

    found_tech = [kw for kw in tech_keywords if kw in text.lower()]
    return found_tech, hashtags, emails


def build_report(username, profiles, bio_data, tech_keywords, hashtags, emails):
    return {
        "username": username,
        "platforms_found": profiles,
        "instagram_bio": bio_data,
        "tech_keywords": tech_keywords,
        "hashtags": hashtags,
        "emails": emails,
        "exposure_score": len(profiles) + len(emails) + len(tech_keywords)
    }


def main():
    welcome_banner()
    username, output_file = ask_user()

    # Step 1: Sherlock scan
    profiles = scan_with_sherlock(username)

    # Step 2: Instagram scraping
    insta_bio = scrape_instagram_bio(username)

    # Step 3: NLP-style parsing
    tech, tags, mails = extract_keywords_and_emails(insta_bio or "")

    # Step 4: Create final report
    report = build_report(username, profiles, insta_bio, tech, tags, mails)

    # Step 5: Show results
    cprint(json.dumps(report, indent=4), "green")

    # Optional: save
    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=4)
        cprint(f"\nReport saved to {output_file}", "yellow")


if __name__ == "__main__":
    main()
