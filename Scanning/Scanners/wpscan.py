import os
import subprocess
import json

def get_wpscan_api_token(file_path='configs.txt'):
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('WPScan_API_token='):
                return line.strip().split('=')[1]
    raise ValueError('WPScan_API_token not found in the config file')

def run_wpscan(urls, api_token='', output_file='scan_reports/wpscan.json'):
    try:
        api_token=get_wpscan_api_token()
    except ValueError:
        print("No API token, continuing scan without one")

    # Ensure the output directory exists
    output_dir = os.path.dirname(output_file)
    os.makedirs(output_dir, exist_ok=True)
    print("Starting WPScan")
    
    # Initialize an empty list to store results
    combined_results = []

    for target_url in urls:
        # Command to run WPScan
        command = ['wpscan', '--url', target_url, '--enumerate', 'u', '--format', 'json']
        
        # Add API token to command if provided
        if api_token:
            command.extend(['--api-token', api_token])
        
        try:
            # Run the WPScan command
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            
            # Parse the JSON output
            wpscan_output = json.loads(result.stdout)
            
            # Append the output to the combined results
            combined_results.append({
                'url': target_url,
                'scan_result': wpscan_output
            })
            
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while scanning {target_url}: {e.stderr}")
            combined_results.append({
                'url': target_url,
                'scan_result': f"Error occurred: {e.stderr}"
            })
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON output for {target_url}: {e}")
            combined_results.append({
                'url': target_url,
                'scan_result': f"JSON decode error: {e}"
            })
    
    # Write the combined results to the output file
    with open(output_file, 'w') as file:
        json.dump(combined_results, file, indent=4)
    
    # Print or process the combined output
    print("Finished WPScan")
    
    return combined_results

