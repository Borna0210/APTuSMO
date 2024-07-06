import psutil

def list_network_connections():
    try:
        connections = psutil.net_connections()
        results = "Network connections:\n"
        for conn in connections:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            results += f"Local Address: {laddr}, Remote Address: {raddr}, Status: {conn.status}\n"
        return results
    except Exception as e:
        return f"Error listing network connections: {str(e)}\n"