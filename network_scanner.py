import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ipaddress
from datetime import datetime
import csv


class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("800x400")

        self.temp_results = []

        self.create_widgets()

    def create_widgets(self):
        # Three-dot button for options
        self.options_button = tk.Button(self.root, text="⋮", font=("Arial", 16), bd=0, relief="flat")
        self.options_button.pack(anchor="ne", padx=10, pady=10)
        self.options_button.bind("<Button-1>", self.show_options_menu)

        # Options menu
        self.options_menu = tk.Menu(self.root, tearoff=0)
        self.options_menu.add_command(label="Save Results", command=self.save_results)
        self.options_menu.add_command(label="View Results", command=self.view_results)

        # Input field and scan button
        tk.Label(self.root, text="Enter Target IP:").pack(pady=5)
        self.ip_entry = tk.Entry(self.root, width=40)
        self.ip_entry.pack(pady=5)

        self.scan_button = tk.Button(self.root, text="Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Treeview to display results
        self.tree = ttk.Treeview(self.root, columns=("IP Address", "MAC Address", "OS", "Timestamp"), show="headings")
        self.tree.heading("IP Address", text="IP Address")
        self.tree.heading("MAC Address", text="MAC Address")
        self.tree.heading("OS", text="Operating System")
        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.pack(pady=10, fill="both", expand=True)

    def get_mac_vendor(self, mac):
        android_prefixes = ["00:1A:11", "00:12:BB", "3C:5A:B4"]
        ios_prefixes = ["F0:D1:A9", "A4:B1:97", "00:17:F2"]
        cisco_prefixes = ["00:1E:49", "00:23:04", "00:25:45"]

        mac_prefix = mac.upper()[:8]

        if any(mac_prefix.startswith(p) for p in android_prefixes):
            return "Android"
        elif any(mac_prefix.startswith(p) for p in ios_prefixes):
            return "iOS"
        elif any(mac_prefix.startswith(p) for p in cisco_prefixes):
            return "Cisco/Networking Device"
        return None

    def get_subnet(self, ip):
        try:
            ip_obj = ipaddress.ip_network(ip, strict=False)
            if ip_obj.prefixlen == 32:
                first_octet = int(str(ip_obj.network_address).split('.')[0])
                if first_octet <= 127:
                    return f"{ip_obj.network_address}/8"
                elif first_octet <= 191:
                    return f"{ip_obj.network_address}/16"
                else:
                    return f"{ip_obj.network_address}/24"
            return str(ip_obj)
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address format.")
            return None

    def scan(self, ip):
        subnet = self.get_subnet(ip)
        if not subnet:
            return []

        arp_req_frame = scapy.ARP(pdst=subnet)
        broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
        answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
        result = []
        for i in range(0, len(answered_list)):
            ip_address = answered_list[i][1].psrc
            mac_address = answered_list[i][1].hwsrc
            os_type = self.detect_os(ip_address, mac_address)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current timestamp
            client_dict = {"ip": ip_address, "mac": mac_address, "os": os_type, "timestamp": timestamp}
            result.append(client_dict)
        return result

    def detect_os(self, ip, mac):
        try:
            syn_packet = scapy.IP(dst=ip) / scapy.TCP(dport=80, flags="S")
            response = scapy.sr1(syn_packet, timeout=1, verbose=False)

            if response and response.haslayer(scapy.IP):
                ttl = response[scapy.IP].ttl
                window_size = response[scapy.TCP].window if response.haslayer(scapy.TCP) else None
                df_flag = response[scapy.IP].flags.DF

                vendor_os = self.get_mac_vendor(mac)
                if vendor_os:
                    return vendor_os

                if ttl <= 32:
                    os_guess = "Embedded Device"
                elif ttl <= 64:
                    os_guess = "Linux"
                elif ttl == 64 and window_size == 5840:
                    os_guess = "Unix/macOS/Linux"
                elif ttl == 255:
                    os_guess = "iOS"
                elif ttl <= 128:
                    os_guess = "Windows"
                elif ttl in [254, 255]:
                    os_guess = "Cisco/Networking Device"
                else:
                    os_guess = "Unknown"

                if df_flag:
                    os_guess += " (DF Set)"
                if window_size:
                    os_guess += f" (Win Size: {window_size})"

                return os_guess
        except Exception as e:
            return "Unknown"

    def display_result(self, result):
        for row in self.tree.get_children():
            self.tree.delete(row)

        if result:
            for entry in result:
                self.tree.insert("", "end", values=(entry["ip"], entry["mac"], entry["os"], entry["timestamp"]))
        else:
            messagebox.showinfo("Scan Result", "No devices found on the network.")

    def save_results(self):
        if not self.temp_results:
            messagebox.showwarning("Save Error", "No results to save.")
            return

        # Open a file dialog to choose the save location and file name
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if file_path:
            try:
                with open(file_path, mode="w", newline="") as file:
                    writer = csv.DictWriter(file, fieldnames=["ip", "mac", "os", "timestamp"])
                    writer.writeheader()
                    writer.writerows(self.temp_results)
                messagebox.showinfo("Save Success", "Results saved successfully!")
            except Exception as e:
                messagebox.showerror("Save Error", f"An error occurred while saving: {e}")

    def view_results(self):
        if not self.temp_results:
            messagebox.showwarning("View Error", "No results to view.")
            return

        # Create a new window to display the results
        result_window = tk.Toplevel(self.root)
        result_window.title("Scan Results")
        result_window.geometry("800x400")

        # Create a Treeview widget to display the results
        result_tree = ttk.Treeview(result_window, columns=("IP Address", "MAC Address", "OS", "Timestamp"), show="headings")
        result_tree.heading("IP Address", text="IP Address")
        result_tree.heading("MAC Address", text="MAC Address")
        result_tree.heading("OS", text="Operating System")
        result_tree.heading("Timestamp", text="Timestamp")
        result_tree.pack(pady=10, fill="both", expand=True)

        # Insert the results into the Treeview
        for entry in self.temp_results:
            result_tree.insert("", "end", values=(entry["ip"], entry["mac"], entry["os"], entry["timestamp"]))

    def start_scan(self):
        target_ip = self.ip_entry.get().strip()
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP Address or range.")
            return
        try:
            scanned_output = self.scan(target_ip)
            self.display_result(scanned_output)
            # Store the results temporarily
            self.temp_results = scanned_output
        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred: {e}")

    def show_options_menu(self, event):
        # Display the options menu at the cursor's position
        self.options_menu.post(event.x_root, event.y_root)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()