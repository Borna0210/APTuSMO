import subprocess
import os
def whatweb_scan(target_urls):
    print("Starting WhatWeb scan")
    all_outputs = []
    
    for target_url in target_urls:
        try:
            # Define WhatWeb command options
            command = [
                'whatweb',
                '--color=never',           # Disable color in output
                '-a', '1',                 # Set aggression level to 3 (Aggressive)
                '-v',                      # Enable verbose output
                '--user-agent', 'Mozilla/5.0 (compatible; WhatWeb/0.5.5; +https://www.morningstarsecurity.com/research/whatweb)',  # Custom user-agent
                target_url
            ]

            # Execute the WhatWeb command
            result = subprocess.run(command, capture_output=True, text=True)

            # Collect the output
            all_outputs.append(result.stdout)
        except Exception as e:
            print(f"An error occurred while scanning {target_url}: {e}")
    
    # Write all outputs to a single file
    combined_output = "\n".join(all_outputs)
    write_output_to_file(combined_output, 'scan_reports/whatweb.txt')
    
    return combined_output

def write_output_to_file(output, file_path):
    try:
        with open(file_path, 'w') as file:
            file.write(output + '\n')
        print(f"Finished WhatWeb scan")
    except Exception as e:
        print(f"An error occurred while writing to file {file_path}: {e}")