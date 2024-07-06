import subprocess
import os

def harvester_scan(target_url, data_limit):
    try:
        print("Starting theHarvester scan")
        # Building the command
        target = target_url.split('//')[1].split('/')[0]
        command = ['theHarvester', '-d', target, '-l', str(data_limit), '-b', 'all']

        # Execute the command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Capture the output
        output, errors = process.communicate()

        if process.returncode == 0:
            # Print the output
            print("theHarvester Output:\n", output)

            # Write the output to a file
            output_path = os.path.join('scan_reports', 'harvester.txt')
            with open(output_path, 'w') as f:
                f.write(output)
            print(f"Output written to {output_path}")
        else:
            print("Errors:\n", errors)
        print("Finished theHarvester scan")

    except Exception as e:
        print(f"An error occurred: {e}")
