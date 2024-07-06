import http.client
import requests
import subprocess
from bs4 import BeautifulSoup
import whois
import sys,os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def run_whois(query):
    try:
        # Remove protocol (http:// or https://) if present
        if query.startswith('http://') or query.startswith('https://'):
            query = query.split('//')[1].split('/')[0]

        result = subprocess.run(['whois', query], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running whois for {query}: {e.stderr}"

def fetch_webpage_title(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.title.text if soup.title else "No title found"
    except requests.RequestException as e:
        return f"Error fetching webpage title for {url}: {e}"

def gather_information(targets, mode, output_file='scan_reports/whois.txt'):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        for target in targets:
            print(f"Starting information gathering for {target}")
            f.write(f"Information for {target}:\n")

            # Whois information
            whois_info = run_whois(target)
            f.write("Whois Information:\n")
            f.write(whois_info + "\n")

            # Additional information for web mode
            if mode == 'web':
                webpage_title = fetch_webpage_title(f"{target}")
                f.write("\nTitle of Webpage:\n")
                f.write(webpage_title + "\n")

            f.write("\n" + "="*50 + "\n\n")

            print(f"Information for {target} gathered.")