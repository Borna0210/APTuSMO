import os

def check_file_permissions(file_path):
    try:
        stat = os.stat(file_path)
        permissions = oct(stat.st_mode)[-3:]
        return f"File permissions for {file_path}: {permissions}\n"
    except Exception as e:
        return f"Error checking permissions for {file_path}: {str(e)}\n"

