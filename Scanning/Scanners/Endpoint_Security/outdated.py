import subprocess
import json

def check_updates():
    try:
        # Run 'sudo apt update' to refresh package list
        subprocess.run(['sudo', 'apt', 'update'], check=True)
        # Run 'apt list --upgradable' to list upgradable packages
        result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
        
        # Process the output to show upgradable packages
        packages = result.stdout.split('\n')
        upgradable = [pkg for pkg in packages if '/' in pkg]
        output = "Upgradable packages:\n"
        for pkg in upgradable:
            output += f"{pkg.split('/')[0]}\n"
        return output
    except subprocess.CalledProcessError as e:
        return f"Error during update check: {str(e)}\n"