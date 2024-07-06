import subprocess
import os

def perform_dig(target, record_type='ANY'):
    try:
        if target.startswith('http://') or target.startswith('https://'):
                target = target.split('//')[1].split('/')[0]  # Remove 'http://' or 'https://' and path
        result = subprocess.run(
            ['dig', target, record_type], capture_output=True, text=True
        )
        with open('scan_reports/dig.txt', 'w') as f:
            f.write(f"\nDNS Lookup (dig - {record_type} records) for {target}:\n")
            f.write(result.stdout)
    except subprocess.CalledProcessError as e:
        with open('scan_reports/dig.txt', 'w') as f:
            f.write(f"Error performing DNS lookup (dig): {e}\n")

def run_dns_scans(targets):
    print("Starting DNS Scans")
    with open('scan_reports/dns_scans.txt', 'w') as f:
        for target in targets:
            # Extract hostname from URL if needed
            if target.startswith('http://') or target.startswith('https://'):
                target = target.split('//')[1].split('/')[0]  # Remove 'http://' or 'https://' and path

            commands = [
                f"nmap -n -v -Pn -sV -p 53 --script dns-nsid {target}",
                f"dig AXFR @{target}",
                f"dig NS {target}",
                f"dig +norecurse -t ns . @{target}"
            ]
            for command in commands:
                f.write(f"\nRunning command: {command}\n")
                output = run_command(command)
                f.write(output)
    print("Finished DNS Scans")

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr
    except Exception as e:
        return f"An error occurred while running command {command}: {e}\n"
