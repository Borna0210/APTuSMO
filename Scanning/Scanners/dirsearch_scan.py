import subprocess
import os


def run_dirsearch(targets, extensions):
    # Define the output file paths
    output_file_path = 'scan_reports/dirsearch.txt'
    temp_output_file_path = 'scan_reports/temp_dirsearch.txt'
    print("Starting Dirsearch")

    # Create the output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    
    # Create or clear the output file
    with open(output_file_path, 'w') as output_file:
        output_file.write("")  # Clear the file

    for target in targets:
        # Determine if the target is a URL or an IP address
        if not target.startswith('http://') and not target.startswith('https://'):
            target = f'http://{target}'
        

        cmd = [
            'python3', 'Scanning/Scanners/dirsearch/dirsearch.py',
            '-u', target,
            '-e', extensions,
            '--output', temp_output_file_path,
            '--format=simple',
            '-t 50'
        ]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Check if the command executed successfully
        if process.returncode == 0:
            # Check if the temporary output file exists
            if os.path.exists(temp_output_file_path):
                print(f"Dirsearch completed successfully for {target}.")
                # Append the output to the combined file
                with open(output_file_path, 'a') as output_file:
                    output_file.write(f"\nResults for {target}:\n")
                    with open(temp_output_file_path, 'r') as temp_output_file:
                        output_file.write(temp_output_file.read())
                    output_file.write("\n" + "="*80 + "\n")
                # Remove the temporary file
                os.remove(temp_output_file_path)
                os.rmdir('reports')
            else:
                output_file.write(f"Dirsearch did not create the temporary output file for {target}.")
        else:
            print(f"Dirsearch encountered an error for {target}.")
            print(stderr.decode())