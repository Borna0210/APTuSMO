import re
import os
import pyshark
import json
from fpdf import FPDF
from bs4 import BeautifulSoup

def clean_text(text):
    """Clean text to ensure compatibility with the PDF encoding."""
    return text.encode('latin-1', 'replace').decode('latin-1')

def parse_report(file_path):
    """Parse a report file and handle potential encoding issues."""
    with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
        return file.read()

def summarize_traceroute(file_path):
    """Summarize a traceroute report by extracting relevant lines."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []
    for i in range(2, len(lines)):
        if re.search(r'<syn', lines[i], re.IGNORECASE):
            summary_lines.extend(lines[i-2:i+1])
            summary_lines.append('')  # Add an empty line for separation

    return "\n".join(summary_lines)

def summarize_endpoint_scan(file_path):
    """Summarize an endpoint scan report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []
    current_section = ""

    for line in lines:
        if 'scan results for' in line.lower():
            if current_section:
                summary_lines.append("\n" + current_section)
            current_section = line
        elif 'Known viruses' in line or 'Engine version' in line or \
             'Scanned directories' in line or 'Scanned files' in line or \
             'Infected files' in line or 'Data scanned' in line or \
             'Data read' in line or 'Time' in line or 'Start Date' in line or \
             'End Date' in line:
            current_section += "\n" + line
    
    if current_section:
        summary_lines.append("\n" + current_section)
    
    return "\n".join(summary_lines)

def summarize_nmap_scan(file_path):
    """Summarize an Nmap scan report."""
    data = parse_report(file_path)
    lines = data.split('\n')

    summary = []
    recording = False
    skip_content = False
    
    for line in lines:
        if "Nmap scan report for" in line:
            recording = True
        if "Running Vulnerability Detection" in line:
            skip_content = True
        if "Running Top Ports Scan" in line:
            skip_content = False
            continue
        if recording and not skip_content:
            summary.append(line.strip())
        if "NSE: Script Post-scanning" in line:
            summary.append(line.strip())
            if not any("NSE:" in l for l in lines):
                summary.pop()  # Remove if nothing follows "NSE: Script Post-scanning"
            recording = False
            summary.append('')  # Add an empty line for separation

    return "\n".join(summary)

def summarize_dns_scan(file_path):
    """Summarize a DNS scan report, including dig results."""
    data = parse_report(file_path)
    lines = data.split('\n')

    summary = []
    recording = False
    dig_section = []
    capture_dig = False

    for line in lines:
        if "Nmap scan report for" in line:
            recording = True
        if recording:
            summary.append(line.strip())
        if "NSE: Script Post-scanning" in line:
            recording = False
            summary.append('')  # Add an empty line for separation

    # Extract dig results
    for line in lines:
        if "Running command: dig" in line:
            capture_dig = True
        if capture_dig:
            dig_section.append(line.strip())
        if ";; Query time" in line or ";; connection timed out" in line:
            capture_dig = False

    summary.append("\nDig Results:")
    summary.extend(dig_section)

    return "\n".join(summary)

def summarize_dirsearch(file_path):
    """Summarize a Dirsearch report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    interesting_results = []
    for line in lines:
        if any(keyword in line.lower() for keyword in ["admin", "login", "config", "backup", "secret", "password"]):
            interesting_results.append(line)
    return "\n".join(interesting_results[:10])  # Limit to 10 interesting results

def summarize_exploits_log(file_path):
    """Summarize the exploits log by extracting the first few executing exploit entries."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []
    count = 0
    for line in lines:
        if 'executing exploit' in line.lower():
            summary_lines.append(line)
            count += 1
            if count >= 5:  # Limit to first 5 entries
                break
    return "\n".join(summary_lines)

def summarize_pcap(file_path):
    """Summarize a PCAP file."""
    capture = pyshark.FileCapture(file_path)
    decoded_packets = []

    for packet in capture:
        try:
            packet_info = {
                'No': packet.number,
                'Time': packet.sniff_time,
                'Source': packet.ip.src,
                'Destination': packet.ip.dst,
                'Protocol': packet.highest_layer,
                'Length': packet.length,
                'Info': str(packet)
            }
            decoded_packets.append(packet_info)
        except AttributeError:
            # Some packets might not have the IP layer
            continue

    capture.close()
    
    summary = "\n".join([f"Packet {pkt['No']}: {pkt['Time']} {pkt['Source']} -> {pkt['Destination']} {pkt['Protocol']} {pkt['Length']} bytes" for pkt in decoded_packets])
    return summary

def clean_json_data(json_str):
    """Clean JSON data by ensuring it has valid syntax."""
    # Replace single quotes with double quotes
    json_str = json_str.replace("'", '"')
    # Remove any trailing commas
    json_str = re.sub(r',\s*}', '}', json_str)
    json_str = re.sub(r',\s*]', ']', json_str)
    # Wrap the JSON data in an array if it's not already
    if not json_str.strip().startswith('['):
        json_str = f'[{json_str}]'
    return json_str

def summarize_nessus(file_path):
    """Summarize Nessus JSON data into a formatted table."""
    with open(file_path, 'r') as f:
        data = f.read()
    
    # Clean the JSON data
    data = clean_json_data(data)
    
    # Load JSON data
    data = json.loads(data)
    
    summary_lines = ["Vuln Index | Plugin ID | Plugin Name | Severity | Plugin Family | Count",
                     "-----------|-----------|-------------|----------|---------------|------"]
    
    for vuln in data:
        summary_lines.append(f"{vuln['vuln_index']}          | {vuln['plugin_id']}     | {vuln['plugin_name']} | {vuln['severity']}        | {vuln['plugin_family']}      | {vuln['count']}")
    
    return "\n".join(summary_lines)

def summarize_ffuf(file_path):
    """Summarize a FFUF report by removing unnecessary lines."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = [line for line in lines if not line.startswith('#')]
    return "\n".join(summary_lines)

def summarize_wpscan(file_path):
    """Summarize a WPScan report."""
    data = parse_report(file_path)
    try:
        json_data = json.loads(data)
        summaries = []

        for entry in json_data:
            if 'scan_result' in entry and isinstance(entry['scan_result'], str) and entry['scan_result'].startswith("Error"):
                summaries.append(f"Error in scanning {entry['url']}: {entry['scan_result']}")
            elif 'scan_result' in entry and isinstance(entry['scan_result'], dict):
                scan_result = entry['scan_result']
                banner = scan_result.get('banner', {})
                interesting_findings = scan_result.get('interesting_findings', [])
                main_theme = scan_result.get('main_theme', {})

                summary = [
                    f"URL: {entry['url']}",
                    f"Target IP: {scan_result.get('target_ip', 'N/A')}",
                    f"WPScan Version: {banner.get('version', 'N/A')}",
                    f"Start Time: {scan_result.get('start_time', 'N/A')}",
                    f"End Time: {scan_result.get('stop_time', 'N/A')}",
                    f"Elapsed Time: {scan_result.get('elapsed', 'N/A')} seconds",
                    "\nInteresting Findings:",
                ]
                for finding in interesting_findings:
                    summary.append(f" - {finding['to_s']}: {finding['url']}")
                
                summary.append("\nMain Theme:")
                summary.append(f" - Theme Name: {main_theme.get('style_name', 'N/A')}")
                summary.append(f" - Version: {main_theme.get('version', {}).get('number', 'N/A')}")
                summary.append(f" - Description: {main_theme.get('description', 'N/A')}")
                
                summaries.append("\n".join(summary))
        
        return "\n\n".join(summaries)
    
    except json.JSONDecodeError:
        return "Invalid JSON data."

def summarize_arp(file_path):
    """Summarize an ARP report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    return "\n".join(lines)

def summarize_harvester(file_path):
    """Summarize a Harvester report."""
    data = parse_report(file_path)
    summary_lines = []
    capture = False
    for line in data.split('\n'):
        if '[*] Interesting Urls found' in line:
            capture = True
        if capture:
            summary_lines.append(line)
    return "\n".join(summary_lines)

def summarize_iot_scan(file_path):
    """Summarize an IoT scan report."""
    data = parse_report(file_path)
    return data

def summarize_whatweb(file_path):
    """Summarize a WhatWeb report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []
    for line in lines:
        if 'WhatWeb report' in line or 'Status' in line or 'Title' in line or 'IP' in line or 'Country' in line or 'Detected Plugins' in line:
            summary_lines.append(line)
        if 'HTTP Headers' in line:
            break  # Stop after detected plugins section
    return "\n".join(summary_lines)

def summarize_whois(file_path):
    """Summarize a Whois report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    return "\n".join(lines[:50])  # Limit to first 50 lines

def summarize_nikto(file_path):
    """Summarize a Nikto report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []
    for line in lines:
        if '+ ' in line:
            summary_lines.append(line)
    return "\n".join(summary_lines)

def summarize_sublister(file_path):
    """Summarize a Sublister report."""
    data = parse_report(file_path)
    summary_lines = [line for line in data.split('\n') if line]
    return "\n".join(summary_lines)

def summarize_burp_scan(file_path):
    """Summarize a Burp scan report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []
    capture = False
    for line in lines:
        if 'INFO - Scan issues' in line:
            capture = True
        if capture:
            summary_lines.append(line)
    return "\n".join(summary_lines)

def summarize_dig(file_path):
    """Summarize a Dig report."""
    data = parse_report(file_path)
    return data

def summarize_waf(file_path):
    """Summarize a WAF (Web Application Firewall) report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []

    for line in lines:
        if '[+]' in line or '[-]' in line or '[~]' in line or '[*]' in line:
            summary_lines.append(line.strip())

    return "\n".join(summary_lines)

def summarize_hydra(file_path):
    """Summarize a Hydra report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []

    for line in lines:
        if '[DATA]' in line or '[80][http-post-form]' in line or '[ERROR]' in line:
            summary_lines.append(line.strip())
    
    return "\n".join(summary_lines)

def summarize_sqlmap(file_path):
    """Summarize an SQLMap report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []

    for line in lines:
        if '[INFO]' in line or '[ERROR]' in line or '[WARNING]' in line:
            summary_lines.append(line.strip())

    return "\n".join(summary_lines)

def summarize_xssstrike(file_path):
    """Summarize an XSSStrike report."""
    data = parse_report(file_path)
    lines = data.split('\n')
    summary_lines = []

    for line in lines:
        if '[~]' in line or '[+]' in line or '[-]' in line or '[!]' in line:
            summary_lines.append(line.strip())
    
    return "\n".join(summary_lines)

def summarize_wafninja(file_path):
    """Summarize a WAFNinja HTML report."""
    data = parse_report(file_path)
    soup = BeautifulSoup(data, 'html.parser')

    # Extract key information from the WAFNinja HTML
    summary_lines = []

    # Extract table rows
    rows = soup.find_all('tr')
    for row in rows:
        cells = row.find_all('td')
        if cells:
            summary_lines.append(" | ".join(cell.get_text(strip=True) for cell in cells))

    return "\n".join(summary_lines)

def summarize_shodan(file_path):
    """Summarize a Shodan HTML report."""
    data = parse_report(file_path)
    soup = BeautifulSoup(data, 'html.parser')

    # Extract key information from the Shodan HTML
    summary_lines = []

    # Extract title
    title = soup.title.string if soup.title else "No title found"
    summary_lines.append(f"IP Address: {title}")

    # Extract IP address, hostname, organization, and ASN
    ip_address = soup.find('h1').get_text(strip=True) if soup.find('h1') else "No IP address found"
    

    hostname = soup.find('td', text='Hostnames').find_next_sibling('td').get_text(strip=True) if soup.find('td', text='Hostnames') else "No hostname found"
    summary_lines.append(f"Hostname: {hostname}")

    organization = soup.find('td', text='Organization').find_next_sibling('td').get_text(strip=True) if soup.find('td', text='Organization') else "No organization found"
    summary_lines.append(f"Organization: {organization}")

    asn = soup.find('td', text='ASN').find_next_sibling('td').get_text(strip=True) if soup.find('td', text='ASN') else "No ASN found"
    summary_lines.append(f"ASN: {asn}")

    # Extract open ports and their corresponding services
    ports = soup.find_all('h6', {'class': 'grid-heading'})
    if ports:
        summary_lines.append("Open Ports:")
        for port in ports:
            port_number_tag = port.find('strong')
            service_tag = port.find_next('em')
            port_number = port_number_tag.get_text(strip=True) if port_number_tag else None
            service = service_tag.get_text(strip=True) if service_tag else None
            if port_number and service:
                summary_lines.append(f" - Port {port_number}: {service}")
    else:
        summary_lines.append("No open ports found")

    # Extract vulnerabilities if present
    vulnerabilities = soup.find_all('a', class_='cve-tag')
    if vulnerabilities:
        summary_lines.append("Vulnerabilities:")
        for i, vuln in enumerate(vulnerabilities):
            if i >= 10:
                summary_lines.append(f" - and {len(vulnerabilities) - 10} more in the Shodan HTML")
                break
            cve_id = vuln.get_text(strip=True)
            summary_lines.append(f" - {cve_id}")
    else:
        summary_lines.append("No vulnerabilities found")

    return "\n".join(summary_lines)


class PDFWithBookmarks(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bookmarks = []

    def add_section(self, title, content, level=0):
        # Create a bookmark for the section
        bookmark_link = self.add_link()
        self.bookmarks.append((title, self.page_no(), bookmark_link, level))
        
        # Add a new page for the section
        self.add_page()
        self.set_link(bookmark_link, y=self.get_y())
        self.set_font("Arial", 'B', 16)
        self.cell(0, 10, clean_text(title), ln=True, align='C')
        self.set_font("Arial", '', 12)
        self.multi_cell(0, 10, clean_text(content))
        self.ln(10)  # Add a few empty rows before the next section

    def add_bookmarks(self):
        # Add bookmarks at the beginning of the document
        self.set_auto_page_break(auto=False)
        self.add_page()
        self.set_font("Arial", 'B', 16)
        self.cell(0, 10, "Table of Contents", ln=True, align='C')
        self.set_font("Arial", '', 12)
        for title, page_no, bookmark_link, level in self.bookmarks:
            indent = "  " * level
            self.cell(0, 10, f"{indent}{title}", ln=True, link=bookmark_link)
        self.set_auto_page_break(auto=True, margin=15)




def generate_pdf_report(scan_reports_dir, attack_reports_dir, output_file, scan_type):
    """Generate a comprehensive PDF report from scan and attack reports."""
    print("Generating the penetration testing report...")
    pdf = PDFWithBookmarks()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Process scan reports
    for scan_file in sorted(os.listdir(scan_reports_dir)):
        file_path = os.path.join(scan_reports_dir, scan_file)
        if os.path.isfile(file_path):  # Ensure it's a file
            if "traceroute" in scan_file.lower():
                scan_data = summarize_traceroute(file_path)
            elif "endpoint" in scan_file.lower():
                scan_data = summarize_endpoint_scan(file_path)
            elif "nmap" in scan_file.lower():
                scan_data = summarize_nmap_scan(file_path)
            elif "dns" in scan_file.lower():
                scan_data = summarize_dns_scan(file_path)
            elif "dirsearch" in scan_file.lower():
                scan_data = summarize_dirsearch(file_path)
            elif "wireshark.pcap" in scan_file.lower():
                scan_data = summarize_pcap(file_path)
            elif "nessus.json" in scan_file.lower():
                scan_data = summarize_nessus(file_path)
            elif "ffuf.txt" in scan_file.lower():
                scan_data = summarize_ffuf(file_path)
            elif "arp.txt" in scan_file.lower():
                scan_data = summarize_arp(file_path)
            elif "harvester.txt" in scan_file.lower():
                scan_data = summarize_harvester(file_path)
            elif "iot_scan.txt" in scan_file.lower():
                scan_data = summarize_iot_scan(file_path)
            elif "whatweb.txt" in scan_file.lower():
                scan_data = summarize_whatweb(file_path)
            elif "whois.txt" in scan_file.lower():
                scan_data = summarize_whois(file_path)
            elif "nikto.txt" in scan_file.lower():
                scan_data = summarize_nikto(file_path)
            elif "sublister.txt" in scan_file.lower():
                scan_data = summarize_sublister(file_path)
            elif "wpscan.json" in scan_file.lower():
                scan_data = summarize_wpscan(file_path)
            elif "burp_scan.txt" in scan_file.lower():
                scan_data = summarize_burp_scan(file_path)
            elif "waf.txt" in scan_file.lower():
                scan_data = summarize_waf(file_path)
            elif "dig.txt" in scan_file.lower():
                scan_data = summarize_dig(file_path)
            elif "shodan.html" in scan_file.lower():
                scan_data = summarize_shodan(file_path)
            else:
                scan_data = parse_report(file_path)
            pdf.add_section(f"Scan Report: {os.path.basename(scan_file)}", scan_data)

    # Process attack reports
    for attack_file in sorted(os.listdir(attack_reports_dir)):
        file_path = os.path.join(attack_reports_dir, attack_file)
        if os.path.isfile(file_path):  # Ensure it's a file
            if "exploits_log" in attack_file.lower():
                attack_data = summarize_exploits_log(file_path)
            elif "xssstrike" in attack_file.lower():
                attack_data = summarize_xssstrike(file_path)
            elif "sqlmap" in attack_file.lower():
                attack_data = summarize_sqlmap(file_path)
            elif "hydra" in attack_file.lower():
                attack_data = summarize_hydra(file_path)
            else:
                attack_data = parse_report(file_path)
            pdf.add_section(f"Attack Report: {os.path.basename(attack_file)}", attack_data)

    # Process wafninja HTML reports separately
    wafninja_dir = os.path.join(attack_reports_dir, 'wafninja')
    if os.path.exists(wafninja_dir) and os.path.isdir(wafninja_dir):
        for wafninja_file in sorted(os.listdir(wafninja_dir)):
            file_path = os.path.join(wafninja_dir, wafninja_file)
            if os.path.isfile(file_path):
                attack_data = summarize_wafninja(file_path)
                pdf.add_section(f"WAFNinja Report: {os.path.basename(file_path)}", attack_data)

    # Add bookmarks at the beginning of the document
    pdf.add_bookmarks()

    # Save the report to a file
    pdf.output(output_file)
    print(f"Penetration testing report generated, saved to {output_file}")
 

