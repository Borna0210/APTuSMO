
# APTuSMO: Automating Penetration Testing in Complex Network Environments

APTuSMO is a powerful tool designed to automate penetration testing in complex network environments. This tool simplifies the process of identifying vulnerabilities and potential exploits across large networks, making it an essential asset for cybersecurity professionals.

## Table of Contents

- [Modules](#modules)
- [Features](#features)
- [Programs used in APTuSMO](#programswithin)
- [Installation](#installation)
  - [Set Up a Virtual Environment](#set-up-a-virtual-environment)
  - [Install Requirements](#install-requirements)
- [Usage](#usage)
  - [Configuration](#configuration)
    - [Run Configurations](#run-configurations)
    - [API Keys and Paths](#api-keys-and-paths)
    - [Config Example](#config-example)
  - [Starting APTuSMO](#starting-aptusmo)
    - [Run the Main Script](#run-the-main-script)
    - [Quick Start with the Run Script](#quick-start-with-the-run-script)
- [License](#license)
- [Thank you](#thank-you)


## Modules

APTuSMO consists of the following modules:

1. **Scanning**
   - Uses various tools like Nmap and Nessus to scan the network for active hosts and vulnerabilities.

2. **Exploitation**
   - Integrates with Metasploit to identify and exploit vulnerabilities found during the scanning phase.

3. **Reporting**
   - Generates comprehensive reports detailing the findings, vulnerabilities, and potential exploits.

4. **Configuration Management**
   - Manages configurations for different scanning and exploitation tools, ensuring consistency and accuracy.

## Features

- Automated network scanning and vulnerability assessment.
- Integration with Metasploit for automated exploitation.
- Comprehensive reporting of vulnerabilities and exploits.
- Configuration management for maintaining consistent scan settings.
- Supports a variety of network topologies and environments.

## Programs Used in APTuSMO

APTuSMO leverages a suite of powerful programs and tools to automate penetration testing in complex network environments. Here is a detailed overview of each tool and its role in the program:

### Information Gathering
- **TheHarvester**: Gathering emails, subdomains, hosts, employee names, open ports, and banners from public sources.
- **Sublist3r**: Enumerating subdomains of websites using OSINT.
- **WHOIS**: Querying databases to obtain information about domain registration.
- **Dig**: Querying DNS name servers for DNS records and configurations.
- **Shodan**: Finding Internet-connected devices and gathering information about them.

### Scanning
- **Nmap**: Network scanning and security auditing.
  - Host Discovery
  - Port Scanning
  - Service Version Detection
  - OS Detection
  - etc.
- **TCP Traceroute**: Tracing the path packets take from one host to another.
  - Network Path Analysis
  - Latency Measurement
- **WhatWeb**: Identifying web technologies.
  - Technology Fingerprinting
  - Version Detection
  - Vulnerability Detection
- **Dirsearch**: Brute-forcing directories and files on web servers.
  - Content Discovery
  - Security Testing
- **Nikto**: Web server scanning.
  - Vulnerability Scanning
  - Server Testing
- **Tenable Nessus**: Vulnerability scanning.
  - Vulnerability Management
  - Detailed Reporting
- **Burp Suite**: Web application security testing.
  - Web Vulnerability Scanning
  - Proxy Functionality
- **ARP Scan**: Discovering devices on the local network.
  - Network Discovery
- **Wireshark**: Network protocol analysis.
  - Packet Analysis
- **WafW00f**: Web Application Firewall (WAF) detection.

### Exploiting
- **Metasploit Framework**: Developing and executing exploit code against a remote target machine.
  - Exploitation
  - Post-Exploitation
- **Hydra**: Brute-forcing login credentials for various services.
  - Password Cracking
- **SQLMap**: Detecting and exploiting SQL injection flaws.
  - SQL Injection
  - Database Extraction
- **XSSStrike**: Identifying and exploiting XSS vulnerabilities in web applications.
  - XSS Testing
- **WAFNinja**: Bypassing Web Application Firewalls (WAFs).
  - WAF Bypassing

### Endpoint Security Modules
  - Scanning and securing endpoints within the network.
  - Security Auditing


## Installation

To get started with APTuSMO, follow these steps:

1. **Clone the Repository**

   ```bash
   git clone https://github.com/Borna0210/APTuSMO.git
   cd APTuSMO
   ```

### Set Up a Virtual Environment

Create a virtual environment to manage dependencies and run it as sudo.

```bash
sudo su
python3 -m venv venv
source venv/bin/activate
```

### Install Requirements

Before running APTuSMO for the first time, ensure all dependencies and tools are up-to-date:

```bash
chmod +x first_run_updates.sh
./first_run_updates
```


## Usage

### Configuration


Before starting APTuSMO, you need to configure all the API keys, necessary information, and run configurations in the `configs.txt` file. Below are the detailed configuration steps and requirements:

#### Run Configurations

- **General Settings**:
  - **Test Type**: Set to `1` for network penetration test, or `2` for domain penetration test.
  - **Target IP or Network**: Specify the target IP address or network range for the test.
  - **Network Type**: Set to `1` for an internal network scan.
  - **Hydra Scan Needed**: Set to `1` if a Hydra crack scan is needed, `0` if not needed.
  - **Username Wordlist**: Path to the username wordlist.
  - **Password Wordlist**: Path to the password wordlist.
  - **Services to Test**: List of services to test (e.g., `ssh,ftp,http-form-post,telnet`).
  - **Network Interface**: Network interface for Wireshark (e.g., `eth0`).
  - **Domain URL**: Specify the domain for domain penetration test (if applicable).

#### API Keys and Paths

- **WPScan**:
  - **WPScan API Token**: Obtain your WPScan API token and add it to the configuration file.

- **Burp Suite**:
  - **Burp Suite REST API Key**: Obtain the REST API key for Burp Suite and add it to the configuration file.
  - **Burp REST API Script Path**: Download the Burp Suite REST API script from [burp-rest-api releases](https://github.com/vmware/burp-rest-api/releases) and specify the path to the script in the configuration file (e.g., `burp-rest-api.sh`).
  - **Burp REST API User Settings**: Specify the path to your Burp Suite REST API user settings JSON file.

- **Shodan**:
  - **Shodan API Key**: Obtain your Shodan API token and add it to the configuration file.

- **Tenable**:
  - **Tenable API Access Key**: Obtain your Tenable Vulnerability Management access key and add it to the configuration file.
  - **Tenable API Secret Key**: Obtain your Tenable Vulnerability Management secret key and add it to the configuration file.
  - **Tenable Owner ID**: Obtain your owner ID needed for Tenable Web Application Scanning and add it to the configuration file.
  - **Tenable Web Scan Type**: Specify the type of web scan for Tenable Web Application Scanning. It can be `quick`, `basic`, or `standard`.

#### Config Example

```bash
# Run Configurations for APTuSMO

# General Settings
test_type=1  # 1 for network penetration test, 2 for domain penetration test
target_ip_or_network=192.168.100.56  # Target IP address or network range
network_type=1  # 1 for internal network scan
hydra_scan_needed=1  # 1 if Hydra crack scan is needed, 0 if not needed
username_wordlist=Elliot  # Path to the username wordlist
password_wordlist=ER28-0652  # Path to the password wordlist
services_to_test=ssh,ftp,http-form-post,telnet  # List of services to test
network_interface=eth0  # Network interface for Wireshark
domain_url=https://google-gruyere.appspot.com/534573053449819143269586484777699826645  # Domain for domain penetration test

# API Keys and Paths

# WPScan
WPScan_API_token=api_token_here

# Burp Suite
Burp_API_key=api_token_here
Burp_REST_API_script_path=/home/user/Desktop/burp-rest-api.sh
Burp_REST_API_user_json_path=/home/user/Desktop/user.json

# Shodan
Shodan_API_key=api_token_here

# Tenable
Tenable_API_access_key=api_token_here
Tenable_API_secret_key=api_token_here
Tenable_owner_id=id_here

# Tenable web app scans can be quick, basic, or standard in this program
Tenable_web_scan_type=quick
```


### Starting APTuSMO

To start using APTuSMO, follow these steps:

1. **Run the Main Script**:

   If you are setting up for the first time or want to manually control the execution, use the following command:

   ```bash
   python3 APTuSMO.py
   ```

2. **Quick Start with the Run Script**

If you are familiar with the program and prefer a quicker setup, you can use the `run.sh` bash script. This script automates the execution with your predefined settings from the configuration file.

First, make the script executable:

```bash
chmod +x run.sh
```

Then, run the script:

```bash
./run.sh
```

This allows for both detailed control and quick setup based on your preference and familiarity with APTuSMO.


## License

APTuSMO is licensed under the MIT License. See the LICENSE file for more details.


## Thank You

Thank you for using APTuSMO. We appreciate your interest and trust in our tool for automating penetration testing in complex network environments. Your feedback and support are invaluable as we continue to improve and expand the capabilities of APTuSMO. If you have any questions, suggestions, or need assistance, please don't hesitate to reach out.

Happy testing!
