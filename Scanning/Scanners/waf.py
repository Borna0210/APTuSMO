import subprocess

def write_output_to_file(content, filepath, mode='a', clear=False):
    try:
      
        
        # Clear the file if clear flag is set
        if clear:
            mode = 'w'
        
        # Write the content to the file
        with open(filepath, mode) as file:
            file.write(content + '\n')
    except Exception as e:
        print(f"An error occurred while writing to file: {e}")

def waf_scan(target):
    try:
        if isinstance(target, list):
            for i in target:
                run_wafw00f(i, first_run=(i == target[0]))
        else:
            run_wafw00f(target, first_run=True)
    except Exception as e:
        write_output_to_file(f"An error occurred during WAF scan: {e}", 'scan_reports/waf_errors.txt', clear=True)

def run_wafw00f(target, first_run=False):
    try:
        print("Starting wafw00f scan")
        # Construct the wafw00f command
        cmd = ['wafw00f', '-a', target]
        
        # Execute the command
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        # Format the output for better readability
        output = f"Results for {target}:\n{process.stdout}\n"
        errors = f"Errors for {target}:\n{process.stderr}\n"
        
        # Output the results to a file
        if process.stdout:
            write_output_to_file(output, 'scan_reports/waf.txt', clear=first_run)
        if process.stderr:
            write_output_to_file(errors, 'scan_reports/waf_errors.txt', clear=first_run)
        print("Finished wafw00f scan")
    except Exception as e:
        write_output_to_file(f"An error occurred during WAF scan of {target}: {e}", 'scan_reports/waf_errors.txt', clear=first_run)


