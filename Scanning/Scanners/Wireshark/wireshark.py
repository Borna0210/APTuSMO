import pyshark
from scapy.all import wrpcap, Ether

def capture_packets(interface='eth0', packet_count=1000):
    """
    Capture packets on the specified network interface.

    Args:
        interface (str): Network interface to capture packets from.
        packet_count (int): Number of packets to capture.

    Returns:
        list: List of captured packets.
    """
    capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)
    print('Capturing packets...')
    capture.sniff(packet_count=packet_count)
    return capture

def save_packets(packets, filename='scan_reports/wireshark.pcap'):
    """
    Save captured packets to a PCAP file.

    Args:
        packets (list): List of packets to save.
        filename (str): Output file name.
    """
    scapy_packets = [scapy_packet_from_pyshark(packet) for packet in packets]
    print(f'Saving {len(scapy_packets)} packets to {filename}...')
    wrpcap(filename, scapy_packets)

def scapy_packet_from_pyshark(packet):
    """
    Convert PyShark packet to Scapy packet.

    Args:
        packet: PyShark packet object.

    Returns:
        scapy.Packet: Scapy packet object.
    """
    raw_packet = bytes.fromhex(packet.get_raw_packet().hex())
    return Ether(raw_packet)

def wireshark_analysis(interface='eth0'):
    """
    Perform internal penetration testing by capturing packets and saving them to a PCAP file.

    Args:
        interface (str): Network interface to capture packets from.
    """
    print("Starting Wireshark Scan")
    packets = capture_packets(interface=interface)
    save_packets(packets)
    print("Finished Wireshark scan")
