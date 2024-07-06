from Scanning.Scanners.Endpoint_Security.netconnections import list_network_connections
from Scanning.Scanners.Endpoint_Security.outdated import check_updates
from Scanning.Scanners.Endpoint_Security.permissions import check_file_permissions
from Scanning.Scanners.Endpoint_Security.malware import scan_directory_with_clamav


def endpoint_security_scan():
    print("Starting endpoint security scan")

    output_file = "scan_reports/endpoint.txt"

    results = []
    results.append(check_updates())
    results.append(check_file_permissions("/etc/shadow"))
    results.append(list_network_connections())
    results.append(scan_directory_with_clamav())

    with open(output_file, "w") as file:
        for result in results:
            file.write(result)
    print("Finished endpoint security scan")
