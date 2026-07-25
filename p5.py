import os
import struct
import time
from datetime import datetime
import re
from urllib.parse import unquote

def display_menu():
    print("\n=== PCAP Analysis Tool ===")
    print("1. Analyze Global Header")
    print("2. Analyze DHCP Frame")
    print("3. Find Suspect Domains (.top)")
    print("4. Identify Search Engine Activity")
    print("5. Detect Potential Threats")
    print("6. Exit")

def select_pcap_file():
    from tkinter import Tk, filedialog
    Tk().withdraw()
    file_path = filedialog.askopenfilename(title="Select a PCAP file", filetypes=[("PCAP files", "*.pcap")])
    if not file_path:
        print("No file selected.")
        exit()
    return file_path

def analyze_global_header(file_path):
    with open(file_path, 'rb') as f:
        global_header = f.read(24)
        magic_number, version_major, version_minor, _, _, snaplen, network = struct.unpack('<IHHIIII', global_header)
        endianness = "Little-endian" if magic_number == 0xa1b2c3d4 else "Big-endian"
        
        print("\n--- Global Header Analysis ---")
        print(f"Length of Global Header: 24 bytes")
        print(f"Magic Number: {hex(magic_number)} ({endianness})")
        print(f"Version: {version_major}.{version_minor}")
        print(f"SnapLength: {snaplen}")
        print(f"Data Link Type: {network}")

def analyze_dhcp_frame(file_path):
    with open(file_path, 'rb') as f:
        f.seek(24)
        packet_header = f.read(16)
        ts_sec, ts_usec, incl_len, _ = struct.unpack('<IIII', packet_header)
        
        packet_data = f.read(incl_len)
        src_mac = ':'.join(format(b, '02x') for b in packet_data[6:12])
        dst_mac = ':'.join(format(b, '02x') for b in packet_data[0:6])
        
        src_ip = '.'.join(map(str, packet_data[26:30]))
        dst_ip = '.'.join(map(str, packet_data[30:34]))
        
        timestamp = ts_sec + ts_usec / 1e6
        gmt_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        print("\n--- DHCP Frame Analysis ---")
        print(f"Timestamp: {timestamp} seconds since epoch")
        print(f"GMT Time: {gmt_time}")
        print(f"Frame Length: {incl_len} bytes")
        print(f"Source MAC Address: {src_mac}")
        print(f"Destination MAC Address: {dst_mac}")
        print(f"Source IP Address: {src_ip}")
        print(f"Destination IP Address: {dst_ip}")

def find_suspect_domains(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    domains = re.findall(rb'[a-zA-Z0-9.-]+\.top', data)
    
    if domains:
        print("\n--- Suspect Domains Found ---")
        for domain in set(domains):
            print(domain.decode())
    else:
        print("\nNo suspect domains found.")

def identify_search_engine_activity(file_path):
    with open(file_path, 'rb') as f:
        data = f.read().decode('utf-8', errors='ignore')
    
    search_patterns = {
        'Bing': r'bing\.com/search\?q=([^&]+)',
        'Yahoo': r'yahoo\.com/search\?p=([^&]+)'
    }
    
    for engine, pattern in search_patterns.items():
        matches = re.findall(pattern, data)
        if matches:
            print(f"\n--- Search Engine Activity: {engine} ---")
            unique_searches = set()
            for match in matches:
                decoded = unquote(match).replace('+', ' ')
                unique_searches.add(decoded)
            
            print("Keywords Searched:")
            for search in unique_searches:
                print(f"- {search}")
            
            # Find accessed website after search
            accessed_site_pattern = rf'{engine}.+?GET\s(https?://[^\s]+)'
            accessed_site = re.search(accessed_site_pattern, data)
            if accessed_site:
                print(f"\nWebsite Accessed After Search: {accessed_site.group(1)}")
            else:
                print("\nNo clear website access detected after search.")

def detect_potential_threats(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    threats = []

    if re.search(rb'\x00\x14\x00\x15\x00\x16', data):
        threats.append("Potential port scanning detected")

    if re.search(rb'UNION.*SELECT|SELECT.*FROM', data, re.IGNORECASE):
        threats.append("Potential SQL injection attempt detected")

    if re.search(rb'<script>.*</script>', data, re.IGNORECASE):
        threats.append("Potential XSS attempt detected")

    malware_signatures = [rb'trojan', rb'virus', rb'malware', rb'backdoor']
    for signature in malware_signatures:
        if re.search(signature, data, re.IGNORECASE):
            threats.append(f"Potential malware signature detected: {signature.decode()}")

    if re.search(rb'\x00\x01\x00\x00\x00\x00\x00\x00', data):
        threats.append("Unusual DNS query pattern detected")

    if threats:
        print("\n--- Potential Threats Detected ---")
        for threat in threats:
            print(f"- {threat}")
    else:
        print("\nNo immediate threats detected. Further analysis recommended.")

# Main Program Execution
if __name__ == "__main__":
    while True:
        display_menu()
        
        choice = input("\nEnter your choice (1-6): ")
        
        if choice == '6':
            break
        
        pcap_file = select_pcap_file()
        
        if choice == '1':
            analyze_global_header(pcap_file)
        elif choice == '2':
            analyze_dhcp_frame(pcap_file)
        elif choice == '3':
            find_suspect_domains(pcap_file)
        elif choice == '4':
            identify_search_engine_activity(pcap_file)
        elif choice == '5':
            detect_potential_threats(pcap_file)
