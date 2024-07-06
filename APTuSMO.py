import os
import zipfile
from datetime import datetime
from Scanning.Scanning import net, web
from Scanning.Scanners.nmap_scan import perform_host_discovery
from Exploiting.Exploting import run_exploits
from Scanning.Scanners.Helper.validip import *
from PDF.Report import generate_pdf_report

def cleanup_files():
    # Delete report.pdf if it exists
    if os.path.exists('report.pdf'):
        os.remove('report.pdf')
    
    # Delete all files in scan_reports directory
    if os.path.exists('scan_reports'):
        for root, dirs, files in os.walk('scan_reports'):
            for file in files:
                os.remove(os.path.join(root, file))
    
    # Delete all files in attack_reports directory but not subfolders
    if os.path.exists('attack_reports'):
        for root, dirs, files in os.walk('attack_reports'):
            for file in files:
                os.remove(os.path.join(root, file))

def zip_reports(variable_name):
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f'report_{variable_name}_{current_time}.zip'
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        # Add the report PDF file
        if os.path.exists('report.pdf'):
            zipf.write('report.pdf', os.path.relpath('report.pdf'))
        # Add all files in the scan_reports directory
        for root, dirs, files in os.walk('scan_reports'):
            for file in files:
                filepath = os.path.join(root, file)
                zipf.write(filepath, os.path.relpath(filepath))
        # Add all files in the attack_reports directory
        for root, dirs, files in os.walk('attack_reports'):
            for file in files:
                filepath = os.path.join(root, file)
                zipf.write(filepath, os.path.relpath(filepath))
    print(f'All needed penetration testing reports have been zipped into {zip_filename}')

def get_domain():
    while True:
        target_url = input("Put in your domain, i.e. (mywebsite.com): ")
        if target_url == 'X':
            exit(1)
        if is_valid_url(target_url):
            return target_url
        print("Not a proper input format, try again, to exit type the letter X")

def get_network_range():
    while True:
        target_network = input("Put in your IP address or network range, e.g. (192.168.130.0/24): ")
        if target_network == 'X':
            exit(1)
        if is_valid_ip_or_cidr(target_network):
            return target_network
        print("Not a proper input format, try again, to exit type the letter X")

def hydra_scan():
    hid=int(input("Do you need a hydra crack scan, if you do, enter 1, else 0: "))
    uname=''
    passlist=''
    lservices=[]
    if(hid==1):
        uname=input("Do you have your own username wordlist or username, if you do enter the path of it or it, if not, press enter, the standard one will be used: ")
        passlist=input("Do you have your own password wordlist or password, if you do enter the path of it or it, if not, press enter, the standard one will be used: ")
        services=input("Do you have wished services to test, e.g. ftp, http... If you do enter them with commas in between, if not, press enter, the standard one will be used: ")
        if(len(uname)==0):
            uname='/usr/share/wordlists/metasploit/namelist.txt'
        if(len(passlist)==0):
            passlist='/usr/share/wordlists/metasploit/password.lst'
        if(len(services)>0):
            lservices=services.split(',')
        else:
            lservices=["ssh", "ftp", "http"]
    return hid, uname, passlist, lservices

def get_scan_type():
    while True:
        intern_extern = input('Would you like an internal or external network scan? Put 1 for internal, 2 for external: ')
        if intern_extern == 'X':
            exit(1)
        if intern_extern in ['1', '2']:
            return int(intern_extern)
        print("Not a proper input format, try again, to exit type the letter X")


def main():
    cleanup_files()
    choice = input("Do you wish to do a network or a domain penetration test? For network, type 1, for web type 2: ")
    if choice == '1':
        target_network = get_network_range()
        scan_type = get_scan_type()
        hosts = perform_host_discovery(target_network)
        hid,uname,passlist,lservices = hydra_scan()
        net(target_network, scan_type, hosts)
        run_exploits(target_network, "net", hosts, "192.168.100.50", hid, uname,passlist,lservices)
        if scan_type == 1:
            generate_pdf_report('scan_reports', 'attack_reports', 'report.pdf', "internal")
            zip_reports("net_internal")
        elif scan_type == 2:
            generate_pdf_report('scan_reports', 'attack_reports', 'report.pdf', "external")
            zip_reports("net_external")

    elif choice == '2':
        target_url = get_domain()
        web(target_url)
        run_exploits(target_url, "web")
        generate_pdf_report('scan_reports', 'attack_reports', 'report.pdf', "web")
        zip_reports("web")
    elif choice == 'X':
        exit(1)
    else:
        print("Wrong type of input, try again. If you'd like to exit the program, type the letter X")

if __name__ == "__main__":
    main()
