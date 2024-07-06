import sys
import os
import subprocess
from Scanning.Scanners.burp_scan import burp_start
from Scanning.Scanners.iot import detect_iot_devices, shodan_search
from Scanning.Scanners.dns_lookup import perform_dig, run_dns_scans
from Scanning.Scanners.ffuf import run_ffuf
from Scanning.Scanners.dirsearch_scan import run_dirsearch
from Scanning.Scanners.harvester import harvester_scan
from Scanning.Scanners.nessus_scan import *
from Scanning.Scanners.nmap_scan import *
from Scanning.Scanners.nikto import run_nikto_scan
from Scanning.Scanners.scapy_arp import perform_arp_scan
from Scanning.Scanners.sublister import sublister_scan
from Scanning.Scanners.waf import waf_scan
from Scanning.Scanners.whatweb import whatweb_scan
from Scanning.Scanners.wpscan import run_wpscan
from Scanning.Scanners.Helper.validip import is_valid_ip_or_cidr, is_valid_domain, is_valid_url
from Scanning.Scanners.Helper.stringify import list_to_comma_separated_string
from Scanning.Scanners.Wireshark.wireshark import wireshark_analysis
from Scanning.InfoGather.InfoGather import gather_information
from Scanning.InfoGather.tcptraceroute import run_tcptraceroute
from Scanning.Scanners.Endpoint_Security.endpoint import endpoint_security_scan


def perform_internal_scan_workflow(hosts, target_network):
    interface = input("Which interface are you testing, needed for Wireshark (e.g. eth1): ")
    nmap_scanner(hosts)
    perform_arp_scan(hosts)
    run_tcptraceroute(hosts)
    whatweb_scan(hosts)
    waf_scan(hosts)
    run_dirsearch(hosts, 'php,html,js,txt')
    run_ffuf(hosts, 'php,html,js,txt')
    run_nikto_scan(hosts)
    wireshark_analysis(interface)
    detect_iot_devices(hosts)
    run_wpscan(hosts)
    endpoint_security_scan()
    #run_netscan("Internal Network Scan",targets=list_to_comma_separated_string(hosts))
    

def perform_external_scan_workflow(hosts, target_network):
    gather_information(hosts, 'external')
    # nmap_scanner(hosts)
    # run_dns_scans(hosts)
    # run_tcptraceroute(hosts)
    # whatweb_scan(hosts)
    # waf_scan(hosts)
    # run_dirsearch(hosts, 'php,html,js,txt')
    # run_ffuf(hosts, 'php,html,js,txt')
    # run_nikto_scan(hosts)
    # detect_iot_devices(hosts)
    run_wpscan(hosts)
    shodan_search(hosts)
    #run_netscan("External Network Scan",targets=list_to_comma_separated_string(hosts),timeout_min=10)

    

def net(target_network, scan_type, hosts):
    if scan_type == 1:
        print("Started the internal net scan info gathering and scanning phase")
        perform_internal_scan_workflow(hosts, target_network)
        print("Finished the internal net scan info gathering and scanning phase")
    elif scan_type == 2:
        print("Started the external net scan info gathering and scanning phase")
        perform_external_scan_workflow(hosts, target_network)
        print("Finished internal net scan info gathering and scanning phase")



def web(target_url):
    print("Started the web app info gathering and scanning phase")
    gather_information([target_url], 'web')
    # run_tcptraceroute([target_url])
    # perform_dig(target_url)
    # run_dns_scans([target_url])
    # harvester_scan(target_url, 100)
    # sublister_scan(target_url)
    # waf_scan(target_url)
    # whatweb_scan([target_url])
    # run_wpscan([target_url])
    # run_dirsearch([target_url], 'php,html,js,txt') 
    # run_ffuf([target_url], 'php,html,js,txt')
    # run_nikto_scan(target_url)
    burp_start(target_url,100)
    sc_type=get_web_scan_type()
    #run_web_app_scan(target_url,timeout="00:10:00",sc_type=sc_type) 
    print("Finished the web app info gathering and scanning phase")
    

def get_web_scan_type(file_path='configs.txt'):
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('Tenable_web_scan_type='):
                return line.strip().split('=')[1]
    raise ValueError('Tenable_web_scan_type not found in the config file')