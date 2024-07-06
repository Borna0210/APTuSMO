import subprocess
import os
import re

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def run_ffuf(targets, extensions, row_limit=100):
    print("Starting ffuf")
    # Define the output file paths
    output_file_path = 'scan_reports/ffuf.txt'
    wordlist = '/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt'
    truncated_wordlist = 'scan_reports/truncated_wordlist.txt'

    # Create the output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    
    # Create or clear the output file
    with open(output_file_path, 'w') as output_file:
        output_file.write("")  # Clear the file

    # Truncate the wordlist to the first 10,000 lines
    with open(wordlist, 'r') as original, open(truncated_wordlist, 'w') as truncated:
        for i, line in enumerate(original):
            if i >= row_limit:
                break
            truncated.write(line)
    
    for target in targets:
        # Determine if the target is a URL or an IP address
        if not target.startswith('http://') and not target.startswith('https://'):
            target = f'http://{target}'

        cmd = [
            'ffuf',
            '-u', f'{target}/FUZZ',
            '-w', truncated_wordlist,
            '-e', extensions,
            '-of', 'csv',
            '-t', '50'
        ]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Check if the command executed successfully
        if process.returncode == 0:
            print(f"ffuf completed successfully for {target}.")
            # Append the output to the combined file
            with open(output_file_path, 'a') as output_file:
                output_file.write(f"\nResults for {target}:\n")
                output_file.write(strip_ansi_codes(stdout.decode()))
                output_file.write("\n" + "="*80 + "\n")
        else:
            print(f"ffuf encountered an error for {target}.")
            print(stderr.decode())

    # Delete the truncated wordlist after the execution
    if os.path.exists(truncated_wordlist):
        os.remove(truncated_wordlist)


