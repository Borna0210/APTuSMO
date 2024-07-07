import sublist3r
import os


def sublister_scan(target_url):
    try:
        # Suppress terminal output
        devnull = open(os.devnull, 'w')
        
        print("Starting sublister scan")
        target = target_url.split('//')[1].split('/')[0]
        
        subdomains = sublist3r.main(target, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        
        # Write subdomains to file
        output_path = os.path.join('scan_reports', 'sublister.txt')
        with open(output_path, 'w') as f:
            if len(subdomains) == 0:
                f.write("No subdomains found")
            else:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
        
        print("Finished sublister scan")
        return subdomains
        
    except Exception as e:
        # Log any exceptions to a file
        exception_path = os.path.join('scan_reports', 'sublister_exception.txt')
        with open(exception_path, 'w') as f:
            f.write(str(e))
        print(f"An error occurred: {e}")
        return None

    finally:
        # Close the devnull file descriptor
        devnull.close()