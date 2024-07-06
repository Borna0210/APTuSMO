import subprocess
import threading
import time
import os

def get_burp_rest_path(file_path='configs.txt'):
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('Burp_REST_API_script_path='):
                return line.strip().split('=')[1]
    raise ValueError('Burp_REST_API_script_path not found in the config file')

def get_burp_user_path(file_path='configs.txt'):
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('Burp_REST_API_user_json_path='):
                return line.strip().split('=')[1]
    raise ValueError('Burp_REST_API_user_json_path not found in the config file')

def run_burp_api():
    # Define the path to the script and the user configuration file
    script_path = get_burp_rest_path()
    config_file = get_burp_user_path()

    # Construct the command
    command = f"{script_path} --user-config-file={config_file}"

    # Run the command
    try:
        print(f"Running command: {command}")
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        print(f"Burp API stdout:\n{result.stdout}")
        print(f"Burp API stderr:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"CalledProcessError: {e}")
        print(f"Return code: {e.returncode}")
        print(f"Command output:\n{e.output}")
    except Exception as e:
        print(f"Exception: {e}")

def burp_scanning(target, timeout=None):
    cmd = [
        'python3', 'Scanning/Scanners/Burp/burpa/burpa/_burpa.py',
        'scan', '--timeout='+str(timeout), target
    ]
    
    # Ensure the output directory exists
    output_dir = 'scan_reports'
    os.makedirs(output_dir, exist_ok=True)
    
    # Define the output file
    output_file = os.path.join(output_dir, 'burp_scan.txt')

    # Start the subprocess and redirect output to a file
    with open(output_file, 'w') as f:
        print(f"Running Burp scan command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
        
        # Capture any errors and append to the output file
        stderr_output = process.stderr.read()
        if stderr_output:
            with open(output_file, 'a') as f_err:
                f_err.write(f"Error: {stderr_output.strip()}\n")
            print(f"Burp scanning stderr:\n{stderr_output.strip()}")
        
        return_code = process.poll()
        if return_code is not None and return_code != 0:
            with open(output_file, 'a') as f_err:
                f_err.write(f"burp_scanning finished with return code {return_code}\n")
            print(f"burp_scanning finished with return code {return_code}")

def burp_start(target_url, timeout=None):
    # Start the Burp API in a separate thread
    print("Starting burp scan")
    burp_api_thread = threading.Thread(target=run_burp_api)
    burp_api_thread.start()
    
    # # Wait for 60 seconds to ensure the API is running
    time.sleep(60)
    
    # Perform the scanning and report generation
    burp_scanning(target_url, timeout)
    print("Finished burp scan")