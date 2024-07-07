def get_web_scan_type(file_path='configs.txt'):
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('Tenable_web_scan_type='):
                return line.strip().split('=')[1]
    raise ValueError('Tenable_web_scan_type not found in the config file')
    