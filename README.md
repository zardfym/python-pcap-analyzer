# Python Network Traffic Analyzer & Threat Detector

## Overview
This is a custom Python-based network traffic analysis tool designed to parse PCAP (Packet Capture) files and extract critical Layer 2-7 protocol data. It was built entirely from scratch without relying on third-party packet parsing libraries, demonstrating a deep understanding of network protocols, byte-level data unpacking, and algorithmic efficiency.

## Key Features
*   **Protocol Parsing:** Extracts and decodes PCAP Global Headers and DHCP frames using Python's `struct` module for byte-level unpacking.
*   **Threat Detection:** Utilizes signature-based regular expressions (Regex) to identify potential Cross-Site Scripting (XSS) attempts, SQL injections, and port scanning activity.
*   **Search Engine Tracking:** Identifies search engine activity (Bing, Yahoo) and decodes user search queries and subsequently accessed websites.
*   **Malicious Domain Flagging:** Scans for and isolates suspect top-level domains (e.g., `.top`) associated with malicious traffic.
*   **Interactive Interface:** Features a graphical user interface (GUI) built with `Tkinter` for easy file selection, paired with a clean command-line menu for analysis execution.

## Technologies Used
*   **Language:** Python 3
*   **Core Libraries:** `struct`, `re` (Regex), `tkinter`, `datetime`, `urllib.parse`

## How to Run
1. Clone this repository to your local machine.
2. Ensure you have Python 3 installed.
3. Run the main script from your terminal:
   ```bash
   python p5_2.py
