import subprocess
import os

def harvester_scan(target_url, data_limit):
    try:
        print("Starting theHarvester scan")
        # Suppress terminal output
        devnull = open(os.devnull, 'w')

        # Building the command
        target = target_url.split('//')[1].split('/')[0]
        command = ['theHarvester', '-d', target, '-l', str(data_limit), '-b', 'all']

        # Execute the command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Capture the output
        output, errors = process.communicate()

        if process.returncode == 0:
            # Write the output to a file
            output_path = os.path.join('scan_reports', 'harvester.txt')
            with open(output_path, 'w') as f:
                f.write(output)
            print(f"Finished theHarvester scan, output written to {output_path}")
        else:
            # Log errors to a file
            error_path = os.path.join('scan_reports', 'harvester_errors.txt')
            with open(error_path, 'w') as f:
                f.write(errors)
            print(f"Errors logged to {error_path}")

    except Exception as e:
        # Log any exceptions to a file
        exception_path = os.path.join('scan_reports', 'harvester_exception.txt')
        with open(exception_path, 'w') as f:
            f.write(str(e))
        print(f"An error occurred: {e}")

    finally:
        # Close the devnull file descriptor
        devnull.close()

