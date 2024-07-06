import os
import nmap
import subprocess

def perform_host_discovery(target, write=0):
    # Initialize Nmap PortScanner object
    nm = nmap.PortScanner()

    # Perform host discovery to find live hosts in the network
    nm.scan(hosts=target, arguments='-sn')
    hostlist = []
    # Print discovered hosts
    if(write==1):
        with open('scan_reports/nmap.txt', 'w') as f:
            f.write("Discovered Hosts:\n")
            for host in nm.all_hosts():
                f.write(host + "\n")
                hostlist.append(host)
    else:
        for host in nm.all_hosts():
            hostlist.append(host)
    return hostlist

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def nmap_scans(target):
    scans = [
    ("Ping Scan", f"nmap -sn {target}"),
    ("Quick Scan", f"nmap -T4 -F {target}"),
    ("Service Version Detection", f"nmap -sV {target}"),
    ("Operating System Detection", f"nmap -O {target}"),
    ("Aggressive Scan", f"nmap -A {target}"),
    ("Vulnerability Detection", f"nmap {target} -sV --script=vulscan/vulscan.nse"),
    ("Top Ports Scan", f"nmap --top-ports 20 {target}"),
    ("Full TCP Scan", f"nmap -sT {target}"),
    ("SYN Scan", f"nmap -sS {target}"),
    ("UDP Scan", f"nmap -sU {target}"),
    ("ACK Scan", f"nmap -sA {target}"),
    ("FIN Scan", f"nmap -sF {target}"),
    ("Xmas Scan", f"nmap -sX {target}"),
    ("Null Scan", f"nmap -sN {target}"),
    ("Fragment Packets", f"nmap -f {target}"),
    ("Randomize Hosts", f"nmap -D RND:10 {target}"),
    ("Source Port", f"nmap --source-port 53 {target}"),
    ("Decoy Scan", f"nmap -D decoy1,decoy2 {target}"),
    ("Scan Specific Ports", f"nmap -p 80,443 {target}"),
    ("Exclude Hosts", f"nmap {target} --exclude <excluded_hosts>"),
    ("IP Range Scan", f"nmap {target}"),
    ("Subnet Scan", f"nmap {target}/24"),
    ("Default Scripts", f"nmap -sC {target}"),
    ("Vulnerability Scan", f"nmap --script vuln {target}"),
    ("Safe Scripts", f"nmap --script=safe {target}"),
    ("Traceroute", f"nmap --traceroute {target}"),
    ("IPv6 Scan", f"nmap -6 {target}"),
    ("SSL Scan", f"nmap --script ssl-* {target}"),
    ("SMB Scan", f"nmap --script smb-* {target}"),
    ("SSL Cert", f"nmap --script ssl-cert {target}"),
    ("SSL Enum Ciphers", f"nmap --script ssl-enum-ciphers {target}"),
    ("SSL Known Key", f"nmap --script ssl-known-key {target}"),
    ("SMB OS Discovery", f"nmap --script smb-os-discovery {target}"),
    ("SMB Security Mode", f"nmap --script smb-security-mode {target}"),
    ("SMB Shares", f"nmap --script smb-enum-shares {target}"),
    ("SMB Users", f"nmap --script smb-enum-users {target}")
]

    with open('scan_reports/nmap.txt', 'a') as f:
        for name, cmd in scans:
            f.write(f"\nRunning {name}...\n")
            output = run_command(cmd)
            f.write(output)

def run_snmp_scan(target):
    command = f"sudo nmap -sU -p 161 {target} --script snmp-info"
    output = run_command(command)
    with open('scan_reports/nmap.txt', 'a') as f:
        f.write("Running SNMP Scan...\n")
        f.write(output)

def run_ntp_scan(target):
    command = f"sudo nmap -sU -p 123 {target} --script ntp-info"
    output = run_command(command)
    with open('scan_reports/nmap.txt', 'a') as f:
        f.write("Running NTP Scan...\n")
        f.write(output)

def nmap_scanner(nmhosts):
    print("Starting nmap scanning")
    for host in nmhosts:
        perform_host_discovery(host,1)
        nmap_scans(host)
        run_snmp_scan(host)
        run_ntp_scan(host)
    print("nmap scanning finished")

