import re
from urllib.parse import urlparse


def is_valid_ipv4(ip_address):
    # Regular expression for validating a single IPv4 address
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    
    # Check if the IP address matches the IPv4 pattern
    if ipv4_pattern.match(ip_address):
        # Further check if each segment of the IPv4 address is between 0 and 255
        segments = ip_address.split('.')
        if all(0 <= int(segment) <= 255 for segment in segments):
            return True
    return False

def is_valid_cidr(cidr):
    # Regular expression for validating a CIDR notation
    cidr_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
    
    # Check if the CIDR notation matches the pattern
    if cidr_pattern.match(cidr):
        ip_part, subnet_part = cidr.split('/')
        if is_valid_ipv4(ip_part) and 0 <= int(subnet_part) <= 32:
            return True
    return False

def is_valid_ip_or_cidr(input_string):
    # Check if the input string is a valid IPv4 address or CIDR notation
    if is_valid_ipv4(input_string) or is_valid_cidr(input_string):
        return True
    return False


def is_valid_domain(domain):
    # Regular expression for validating a domain name
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,6}$'
    )
    
    # Check if the domain matches the pattern
    if domain_pattern.match(domain):
        return True
    return False

def is_valid_url(url):
    try:
        # Parse the URL
        parsed_url = urlparse(url)
        
        # Extract the domain from the URL
        domain = parsed_url.hostname
        
        # Validate the extracted domain
        if domain and is_valid_domain(domain):
            return True
        return False
    except Exception as e:
        return False