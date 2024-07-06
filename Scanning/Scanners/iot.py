import subprocess
import shodan
import os
import requests

def detect_iot_devices(network_range, output_file='scan_reports/iot_scan.txt'):
    """
    Detect IoT devices on a specified network using Nmap.

    Parameters:
    - network_range: The network range to scan (e.g., '192.168.1.0/24') or a list of specific IP addresses.
    - output_file: The file to write the scan results to (default is 'iot_scan_results.txt').

    Returns:
    - The output of the Nmap scan.
    """
    # Check if network_range is a list and join it into a string of IP addresses
    if isinstance(network_range, list):
        network_range = ' '.join(network_range)
    
    # Define the Nmap command
    command = [
        'nmap',
        '-sV',                        # Service version detection
        '-O',                         # Operating system detection
        '--script=banner,http-title,upnp-info,snmp-info,ftp-anon',
        '-p', '21,22,23,80,161,443,5000,8000-8100',  # Common ports for IoT devices
        network_range                # Target network range or IP addresses
    ]

    command_upnp = [
        'sudo', 'nmap', '-p', '1900', '--script', 'upnp-info', network_range
    ]
    
    command_mqtt = [
        'sudo', 'nmap', '-p', '1883', '--script', 'mqtt-subscribe', network_range
    ]
    

    command_dns_sd = [
        'sudo', 'nmap', '--script', 'dns-service-discovery', '-p', '5353', network_range
    ]
    
    command_mac = [
        'sudo', 'nmap', '-sP', network_range
    ]
  
    try:
        # Run the Nmap command
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        result_upnp = subprocess.run(command_upnp, text=True, capture_output=True, check=True)
        result_mqtt = subprocess.run(command_mqtt, text=True, capture_output=True, check=True)
        result_dns_sd = subprocess.run(command_dns_sd, text=True, capture_output=True, check=True)
        result_mac = subprocess.run(command_mac, text=True, capture_output=True, check=True)

        # Write the output to a file
        with open(output_file, 'w') as file:
            file.write("Nmap Scan Results:\n")
            file.write(result.stdout)
            file.write("\n\nUPNP Scan Results:\n")
            file.write(result_upnp.stdout)
            file.write("\n\nMQTT Scan Results:\n")
            file.write(result_mqtt.stdout)
            file.write("\n\nDNS Service Discovery Results:\n")
            file.write(result_dns_sd.stdout)
            file.write("\n\nMAC Address Scan Results:\n")
            file.write(result_mac.stdout)
        
        # Print the main Nmap scan result
        print(result.stdout)
        
        return result.stdout
        
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e.stderr}")
        return None

def get_shodan_api_key(file_path='configs.txt'):
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('Shodan_API_key='):
                return line.strip().split('=')[1]
    raise ValueError('Shodan_API_key not found in the config file')

def shodan_search(targets,output_file='scan_reports/shodan.txt'):
    # Initialize the Shodan API client
    api_key=get_shodan_api_key()
    api = shodan.Shodan(api_key)
    
    try:
        print("Starting Shodan search")
        with open(output_file, 'w') as file:
            for target in targets:
                try:
                    # Search Shodan
                    host_info = api.host(target)
                    # Write host information to the output file
                    file.write(f"\n\nShodan Information for IP: {host_info['ip_str']}\n")
                    file.write(f"Organization: {host_info.get('org', 'N/A')}\n")
                    file.write(f"Operating System: {host_info.get('os', 'N/A')}\n")
                    file.write("Ports and Banners:\n")
                    for item in host_info['data']:
                        file.write(f"  Port: {item['port']}\n")
                        file.write(f"  Banner: {item['data']}\n")
                        file.write("\n")
                    if(os.path.exists('scan_reports/shodan.html')):
                        os.remove('scan_reports/shodan.html')
                except shodan.APIError as e:
                    # Log the specific error
                    print(f"Shodan Error for target {target}: {e}, your API probably doesn't have high enough privileges, but we'll get the html of the info site'\n")
                    os.remove(output_file)
                    response=requests.get("https://www.shodan.io/host/"+target)
                    with open('scan_reports/shodan.html', 'wb') as file:
                        file.write(response.content)
        print("Finished Shodan search")


    except IOError as e:
        print(f"Error in Shodan search, error writing to output file: {e}")