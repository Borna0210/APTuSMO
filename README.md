
# APTuSMO: Automating Penetration Testing in Complex Network Environments

APTuSMO is a powerful tool designed to automate penetration testing in complex network environments. This tool simplifies the process of identifying vulnerabilities and potential exploits across large networks, making it an essential asset for cybersecurity professionals.

## Table of Contents

- [Acknowledgements](#acknowledgements)
- [Modules](#modules)
- [Features](#features)
- [Programs Used in APTuSMO](#programs-used-in-aptusmo)
- [Installation](#installation)
  - [Set Up a Virtual Environment](#set-up-a-virtual-environment)
  - [Install Requirements](#install-requirements)
- [Usage](#usage)
  - [Configuration](#configuration)
    - [Run Configurations](#run-configurations)
    - [API Keys and Paths](#api-keys-and-paths)
    - [Config Example](#config-example)
  - [Starting APTuSMO](#starting-aptusmo)
    - [Option 1: Step-by-Step Interactive Setup](#option-1-step-by-step-interactive-setup)
    - [Option 2: Quick Run with Predefined Settings](#option-2-quick-run-with-predefined-settings)
- [License](#license)
- [Thank You](#thank-you)



## Acknowledgements

Before proceeding, I would like to extend my heartfelt gratitude to the GitHub projects and companies that have significantly contributed to the development of APTuSMO. These incredible tools and resources have been instrumental in making this program possible. While I have made some modifications to tailor them to APTuSMO, the original projects deserve full credit for their foundational work.

### GitHub Projects
- **[WAFNinja](https://github.com/khalilbijjou/WAFNinja)**: Thank you for providing an excellent tool for bypassing Web Application Firewalls (WAFs). Your project has been a cornerstone in the development of APTuSMO.
- **[XSSStrike](https://github.com/s0md3v/XSStrike)**: Your powerful XSS vulnerability detection tool has greatly enhanced the capabilities of APTuSMO in web application security testing.
- **[Burpa](https://github.com/tristanlatr/burpa)**: Thank you for the Burp Suite automation and integration tool, which has significantly improved the efficiency of web application security testing in APTuSMO.
- **[Burp REST API](https://github.com/vmware/burp-rest-api)**: Special thanks for the Burp REST API, which has enabled seamless integration with Burp Suite for automated security testing.
- **[Dirsearch](https://github.com/maurosoria/dirsearch)**: Your command-line tool for brute-forcing directories and files on web servers has been crucial for content discovery and security testing within APTuSMO.
- **[SQLMap](https://github.com/sqlmapproject/sqlmap)**: Your open-source tool for detecting and exploiting SQL injection flaws has been essential for web application exploitation.

### Companies and Their Products
- **[Tenable](https://www.tenable.com)**: Thank you for your comprehensive vulnerability management solutions, which have been essential for thorough security assessments in APTuSMO.
- **[PortSwigger](https://portswigger.net)**: Your exceptional Burp Suite toolset has provided a robust platform for web application security testing, enabling APTuSMO to deliver high-quality results.
- **[Shodan](https://www.shodan.io)**: Your search engine for Internet-connected devices has been invaluable for information gathering and device discovery.
- **[Nmap](https://nmap.org)**: Your network scanning and security auditing tool has been fundamental to the scanning capabilities of APTuSMO.
- **[Wireshark](https://www.wireshark.org)**: Your network protocol analyzer has provided deep insights into network traffic analysis, enhancing APTuSMO's scanning module.
- **[Rapid7](https://www.rapid7.com)**: Your comprehensive security solutions, especially the Metasploit Framework, have been critical for the exploitation phase of APTuSMO.

Thank you to all the developers, contributors, and companies for your outstanding tools and resources. APTuSMO wouldn't exist without your innovation and dedication to the cybersecurity community. While I have mentioned several key contributors, there are many more who have played an important role in this project's success. To all those who aren't mentioned here, please know that your efforts are deeply appreciated by me and the entire cybersecurity community. Your work makes a significant difference, and for that, we are all extremely grateful.


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

To start using APTuSMO, you have two options: a step-by-step setup to see and answer each configuration question interactively, or a quick run using predefined settings from a configuration file. Choose the option that best suits your needs.

#### Option 1: Step-by-Step Interactive Setup

For those who prefer to see and answer each configuration question interactively, follow these steps:

1. **Run the Main Script**:

   Execute the main script to start the interactive setup. This will guide you through each configuration step, asking for your input as needed.

   ```bash
   python3 APTuSMO.py
   ```

This method provides a detailed and controlled setup process, allowing you to understand and customize each configuration parameter.

#### Option 2: Quick Run with Predefined Settings

For those who are familiar with the program and prefer a faster setup using predefined settings, follow these steps:

1. **Prepare the Configuration File**:

   Ensure that all necessary configuration settings are correctly specified in the `configs.txt` file.

2. **Make the Run Script Executable**:

   Grant execution permissions to the run script.

   ```bash
   chmod +x run.sh
   ```

4. **Run the Script**:

   Execute the run script to automatically set up APTuSMO using the predefined settings from the configuration file.
     
    ```bash
    ./run.sh
    ```

This method allows for a streamlined and efficient setup, leveraging your predefined configurations to quickly deploy APTuSMO.

Choose the method that best fits your workflow and preferences to efficiently configure and run APTuSMO for your penetration testing needs.


## License

APTuSMO is licensed under the MIT License. See the LICENSE file for more details.


## Thank You

Thank you for using APTuSMO. We appreciate your interest and trust in our tool for automating penetration testing in complex network environments. Your feedback and support are invaluable as we continue to improve and expand the capabilities of APTuSMO. If you have any questions, suggestions, or need assistance, please don't hesitate to reach out.

Happy testing!
