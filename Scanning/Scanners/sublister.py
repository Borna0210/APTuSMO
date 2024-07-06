import sublist3r
import os

def sublister_scan(target_url):
    
    target = target_url.split('//')[1].split('/')[0]
    try:
        print("Starting sublister scan")
        subdomains = sublist3r.main(target, 40,savefile=None, ports=None, silent=False, verbose=True, enable_bruteforce=False, engines=None)
        
        # Write subdomains to file
        output_path = os.path.join('scan_reports', 'sublister.txt')
        with open(output_path, 'w') as f:
            if(len(subdomains)==0):
                f.write("No subdomains found")
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        print("Finished sublister scan")
        
        return subdomains
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
