import subprocess
import os

def run_tcptraceroute(targets):
    # Ensure the directory for the report exists
    output_path = 'scan_reports/traceroute.txt'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    print ("Starting tcptraceroute scan")
    with open(output_path, 'w') as f:
        for target in targets:
            try:
                # Determine if the target is a URL or an IP address
                if target.startswith('http://') or target.startswith('https://'):
                    destination = target.split('//')[1].split('/')[0]
                else:
                    destination = target

                for port in ports:
                    cmd = ['sudo', 'tcptraceroute', destination, str(port)]
                    
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()

                    if process.returncode == 0:
                        f.write(f"tcptraceroute completed successfully for {destination} on port {port}.\n")
                        f.write(stdout.decode() + '\n')
                    else:
                        f.write(f"tcptraceroute encountered an error for {destination} on port {port}.\n")
                        f.write(stderr.decode() + '\n')

                    print(f"tcptraceroute for {destination} on port {port} completed.")
            except Exception as e:
                f.write(f"An error occurred while processing {target}: {e}\n")
                print(f"An error occurred while processing {target}: {e}")

ports = [
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # Microsoft-DS
    993,   # IMAPS
    995,   # POP3S
    1433,  # Microsoft SQL Server
    1521,  # Oracle Database
    3306,  # MySQL
    3389,  # Microsoft RDP
    5432,  # PostgreSQL
    8080,  # HTTP (alternative port)
    8443   # HTTPS (alternative port)
]

