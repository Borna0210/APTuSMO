import os
from scapy.all import Ether, ARP, srp

# Define output file and directory
output_dir = 'scan_reports'
output_file = os.path.join(output_dir, 'arp.txt')

# Ensure the output directory exists
os.makedirs(output_dir, exist_ok=True)

def perform_arp_scan(target):
    print("\nPerforming ARP scan:")
    with open(output_file, 'w') as f:
        for trgt in target:
            f.write(f"\nTarget: {trgt}\n")
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=trgt)
            answered, unanswered = srp(arp_request, timeout=2, verbose=False, iface='eth0')
            if answered:
                for sent, received in answered:
                    result = f"IP: {received.psrc}, MAC: {received.hwsrc}\n"
                    f.write(result)
                    print(result, end='')
            else:
                f.write("No response\n")
                print("No response")
    print("Finished ARP scan")