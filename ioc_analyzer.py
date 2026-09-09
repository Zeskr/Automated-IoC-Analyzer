import re
import csv
import time
import requests
import argparse

API_KEY = '82ec6dcfe9371576f58e4239a5a30b09c8798377268eb64b8e36f4fcd7a2284477b881d6bae2093c'
API_URL = 'https://api.abuseipdb.com/api/v2/check'

def extract_ips(log_file):
    """Extracts unique IPs using Regex"""
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    unique_ips = set()
    try:
        with open(log_file, 'r') as file:
            for line in file:
                matches = ip_pattern.findall(line)
                for ip in matches:
                    # Ignore internal/private IPs
                    if not ip.startswith(('10.', '192.168.', '127.')) and not re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip):
                        unique_ips.add(ip)
    except FileNotFoundError:
        print(f"Error: Could not find file {log_file}")
        exit(1)
    return list(unique_ips)

def check_ip_reputation(ip):
    """Queries AbuseIPDB API for specific IP"""
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    try:
        response = requests.get(API_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'IP': ip,
                'Country': data.get('countryCode', 'Unknown'),
                'Abuse_Score': data.get('abuseConfidenceScore', 0),
                'Total_Reports': data.get('totalReports', 0)
            }
    except Exception as e:
        print(f"Error checking {ip}: {e}")
    return None

def main():
    parser = argparse.ArgumentParser(description="Analyze log files for malicious IPs.")
    parser.add_argument('-f', '--file', required=True, help="Path to the log file (e.g., /var/log/auth.log)")
    parser.add_argument('-o', '--output', default="threat_report.csv", help="Output CSV file name")
    args = parser.parse_args()

    print(f"[*] Extracting IPs from {args.file}...")
    ips = extract_ips(args.file)
    print(f"[*] Found {len(ips)} unique external IPs. Querying API...")

    results = []
    for ip in ips:
        print(f"  -> Checking {ip}...")
        report = check_ip_reputation(ip)
        if report:
            results.append(report)
        time.sleep(1)

    if results:
        with open(args.output, 'w', newline='') as csvfile:
            fieldnames = ['IP', 'Country', 'Abuse_Score', 'Total_Reports']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        print(f"[+] Scan complete. Report saved to {args.output}")

if __name__ == '__main__':
    main()
