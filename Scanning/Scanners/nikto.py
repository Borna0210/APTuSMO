import os
import subprocess

# Define the output directory
OUTPUT_DIR = "scan_reports"

def run_nikto_scan(targets):
    print("Starting Nikto scan")
    # Ensure the output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    output_file = os.path.join(OUTPUT_DIR, "nikto.txt")

    # Ensure targets is a list even if a single URL is provided
    if isinstance(targets, str):
        targets = [targets]

    # Run Nikto scan for each target
    with open(output_file, "w") as f:
        for target in targets:
            cmd = f"nikto -h {target} -o {output_file} -maxtime {'20s'}"
            process = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if process.returncode == 0:
                f.write(f"Nikto scan for {target} completed successfully:\n")
                f.write(process.stdout)
                f.write("\n\n")
            else:
                f.write(f"Error running Nikto scan for {target}:\n")
                f.write(process.stderr)
                f.write("\n\n")

            print(f"Nikto scan for {target} completed.")