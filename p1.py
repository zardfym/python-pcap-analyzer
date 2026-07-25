import struct
import tkinter as tk
from tkinter import filedialog
from typing import Dict, Union

LINK_LAYER_TYPES = {
    0: "BSD loopback",
    1: "Ethernet",
    3: "AX.25",
    6: "Token Ring",
    7: "ARCnet",
    8: "SLIP",
    9: "PPP",
    10: "FDDI",
    105: "IEEE 802.11",
    127: "BSD/OS SLIP",
    129: "BSD/OS PPP",
    143: "Linux LAPD"
}

def parse_global_header(header: bytes) -> Dict[str, Union[str, int]]:
    """Parse PCAP global header with protocol validation and enhanced error checking"""
    if len(header) != 24:
        raise ValueError(f"Invalid header length: {len(header)} bytes (expected 24)")

    magic = header[:4]
    endian = determine_endianness(magic)

    try:
        version_major, version_minor = struct.unpack(f"{endian}HH", header[4:8])
        snaplen = struct.unpack(f"{endian}I", header[16:20])[0]
        network = struct.unpack(f"{endian}I", header[20:24])[0]
    except struct.error as e:
        raise ValueError("Header corruption detected") from e

    return {
        'global_header_length': 24,
        'magic_number': magic.hex(),
        'endianness': 'Little Endian' if endian == '<' else 'Big Endian',
        'version': f"{version_major}.{version_minor}",
        'snaplen': snaplen,
        'data_link': LINK_LAYER_TYPES.get(network, f"Unknown (0x{network:x})")
    }

def determine_endianness(magic: bytes) -> str:
    """Validate magic number and determine byte order with extended validation"""
    magic_values = {
        b'\xa1\xb2\xc3\xd4': '>',  # Big-endian
        b'\xd4\xc3\xb2\xa1': '<',  # Little-endian
        b'\xa1\xb2\x3c\x4d': '>',  # Modified big-endian
        b'\x4d\x3c\xb2\xa1': '<'   # Modified little-endian
    }

    if magic not in magic_values:
        raise ValueError(f"Unsupported magic number: {magic.hex()} "
                         f"(known variants: {', '.join(k.hex() for k in magic_values)})")

    return magic_values[magic]

def analyze_pcap() -> None:
    """GUI-driven PCAP analysis with comprehensive error reporting"""
    root = tk.Tk()
    root.withdraw()

    try:
        file_path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        with open(file_path, 'rb') as f:
            header = f.read(24)

        result = parse_global_header(header)
        print("\nPCAP Global Header Analysis Report:")
        for k, v in result.items():
            print(f"{k.replace('_', ' ').title():<22}: {v}")

    except Exception as e:
        print(f"\nAnalysis Error: {str(e)}")
        print("Possible causes:\n- Corrupted file\n- Invalid PCAP format\n- Unsupported variant")

if __name__ == "__main__":
    analyze_pcap()
