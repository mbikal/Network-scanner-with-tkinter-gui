Network Scanner

Overview

This Network Scanner is a Python-based tool that identifies active devices on a local network using ARP scanning. It features a graphical user interface (GUI) built with Tkinter, allowing users to input a target IP range, start scans, view results, and save them for later analysis.

Features

User-Friendly GUI: Built with Tkinter for an interactive experience.

ARP Scanning: Identifies active devices on the network.

MAC Address Resolution: Retrieves MAC addresses of detected devices.

OS Detection: Attempts to identify operating systems.

Results Display: Shows scan results in a structured format.

Save & View Results: Export results as CSV for future reference.

Error Handling: Ensures valid input and provides meaningful feedback.

Requirements

Hardware

Processor: Intel Core i3 or higher (or equivalent AMD)

RAM: 4GB minimum (8GB recommended)

Storage: At least 500MB of free space

Network Adapter: Capable of sending ARP packets

Software

OS: Windows, Linux (Ubuntu/Kali), or macOS

Python: Version 3.8 or later

Dependencies:

scapy (for network scanning)

tkinter (for GUI, included in Python)

ipaddress (for IP validation)

csv & datetime (for logging, included in Python)

prettytable (for structured output)

Installation

Clone the repository:

git clone https://github.com/mbikal/Network-scanner-with-tkinter-gui.git
cd network-scanner

Install dependencies:

pip install scapy prettytable ipaddress

Run the scanner:

python main.py

Usage

Open the application.

Enter the target IP or subnet (e.g., 192.168.1.1/24).

Click the "Scan" button to start.

View the scanned results in the table.

Save results as a CSV file if needed.

Future Improvements

Real-time Monitoring: Continuous network scanning with live updates.

Multithreading: Speed up scanning by running multiple queries simultaneously.

Expanded OS Detection: Improve detection accuracy using more fingerprinting techniques.

Export to Multiple Formats: Support saving results in JSON and XML.

Additional Scanning Methods: Implement other network discovery techniques beyond ARP.

Legal Disclaimer

This tool is intended for ethical and educational purposes only. Ensure you have permission before scanning any network. Unauthorized use may violate laws and regulations.

Contributors

Bikal Barai Magar – Developer

License

This project is licensed under the MIT License. See LICENSE for more details.

