import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import queue 
# New import for the summary feature
from utils.summary_helper import generate_summary

from scanner.nmap_scanner import run_scan, discover_hosts, check_nmap_installed
from utils.file_handler import save_to_file
from utils.network_utils import get_local_ip, get_network_range

class NetworkScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Mapper Pro")
        self.root.geometry("1100x800")
        self.root.configure(bg="#1e1e1e")

        self.results_data = []
        self.devices = [] # Stores dicts: {'ip':..., 'hostname':...}
        self.local_ip = get_local_ip()
        
        # Thread Safe Queue
        self.log_queue = queue.Queue()
        self.scanning = False

        self._setup_ui()
        
        # Check for Nmap installation
        if not check_nmap_installed():
            messagebox.showerror("Error", "Nmap is not installed or not in PATH!\nPlease install Nmap to use this tool.")
            self.root.destroy()
            return

        # Start processing the log queue
        self.root.after(100, self.process_queue)

    def _setup_ui(self):
        # ===== TITLE =====
        tk.Label(self.root, text="NETWORK MAPPER",
                 font=("Helvetica", 24, "bold"),
                 fg="#00FFAA", bg="#1e1e1e").pack(pady=15)

        # ===== MAIN GRID FRAME =====
        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        main_frame.columnconfigure(0, weight=1) # Left Panel
        main_frame.columnconfigure(1, weight=1) # Right Panel

        # ================= LEFT PANEL =================
        left_frame = tk.Frame(main_frame, bg="#2b2b2b", bd=2, relief="groove")
        left_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Header
        tk.Label(left_frame, text="Target Configuration", 
                 font=("Arial", 14, "bold"), fg="white", bg="#2b2b2b").pack(pady=10)

        # Input Frame
        input_frame = tk.Frame(left_frame, bg="#2b2b2b")
        input_frame.pack(padx=10, fill="x")

        tk.Label(input_frame, text="Target IP / Network:", fg="white", bg="#2b2b2b").grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(input_frame, width=30, font=("Consolas", 10))
        self.ip_entry.grid(row=0, column=1, pady=5)
        
        tk.Button(input_frame, text="Use My IP", command=self.fill_my_ip, 
                  bg="#444", fg="white").grid(row=0, column=2, padx=5)

        tk.Label(input_frame, text="Port Range (opt):", fg="white", bg="#2b2b2b").grid(row=1, column=0, sticky="w")
        self.port_entry = tk.Entry(input_frame, width=30, font=("Consolas", 10))
        self.port_entry.grid(row=1, column=1, pady=5)

        # Scan Types
        tk.Label(left_frame, text="Scan Profile", font=("Arial", 12, "bold"), fg="white", bg="#2b2b2b").pack(pady=(15, 5))

        self.scan_type = tk.StringVar(value="Quick Scan")
        scan_frame = tk.Frame(left_frame, bg="#2b2b2b")
        scan_frame.pack(fill="x", padx=10)

        # Columns for radiobuttons
        col1 = tk.Frame(scan_frame, bg="#2b2b2b")
        col1.pack(side="left", expand=True)
        col2 = tk.Frame(scan_frame, bg="#2b2b2b")
        col2.pack(side="left", expand=True)

        basic_opts = ["Quick Scan", "Full Scan", "Host Discovery"]
        adv_opts = ["Service Detection", "Aggressive Scan", "Stealth Scan", "UDP Scan"]

        for opt in basic_opts:
            tk.Radiobutton(col1, text=opt, variable=self.scan_type, value=opt,
                           bg="#2b2b2b", fg="#ccc", selectcolor="#444", anchor="w").pack(fill="x")

        for opt in adv_opts:
            tk.Radiobutton(col2, text=opt, variable=self.scan_type, value=opt,
                           bg="#2b2b2b", fg="#ccc", selectcolor="#444", anchor="w").pack(fill="x")

        # Action Buttons
        self.btn_scan = tk.Button(left_frame, text="START SCAN", bg="#4CAF50", fg="white", 
                                  font=("Arial", 12, "bold"), width=20, height=2,
                                  command=self.start_scan_thread)
        self.btn_scan.pack(pady=20)

        # ================= RIGHT PANEL =================
        right_frame = tk.Frame(main_frame, bg="#2b2b2b", bd=2, relief="groove")
        right_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        tk.Label(right_frame, text="Network Discovery", font=("Arial", 14, "bold"), fg="white", bg="#2b2b2b").pack(pady=10)

        self.btn_net_scan = tk.Button(right_frame, text="Scan My Network", bg="#2196F3", fg="white",
                                      width=20, command=self.scan_network_thread)
        self.btn_net_scan.pack(pady=5)

        tk.Label(right_frame, text="Live Devices:", fg="white", bg="#2b2b2b").pack(pady=(10,0))
        
        # Device Listbox with Scrollbar
        listbox_frame = tk.Frame(right_frame, bg="#2b2b2b")
        listbox_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.device_listbox = tk.Listbox(listbox_frame, width=35, height=10, bg="#111", fg="#00FFAA", font=("Consolas", 9))
        scrollbar = tk.Scrollbar(listbox_frame, orient="vertical", command=self.device_listbox.yview)
        self.device_listbox.config(yscrollcommand=scrollbar.set)
        
        self.device_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.device_listbox.bind("<<ListboxSelect>>", self.on_device_select)

        self.btn_sel_scan = tk.Button(right_frame, text="Scan Selected Device", bg="#9C27B0", fg="white",
                                      width=20, command=self.scan_selected_device_thread)
        self.btn_sel_scan.pack(pady=5)

        self.btn_save = tk.Button(right_frame, text="Save Results", bg="#FF9800", fg="white",
                                  width=20, command=self.save_results)
        self.btn_save.pack(pady=5)

        # === NEW SUMMARY BUTTON ===
        self.btn_summary = tk.Button(right_frame, text="📊 Summary", bg="#607D8B", fg="white",
                                     width=20, command=self.show_summary_popup)
        self.btn_summary.pack(pady=5)

        # ===== STATUS BAR =====
        self.status_var = tk.StringVar(value="Status: Idle")
        self.status = tk.Label(self.root, textvariable=self.status_var, fg="lightgray", bg="#1e1e1e", font=("Arial", 10, "italic"))
        self.status.pack(side="bottom", pady=5)

        # ===== OUTPUT AREA =====
        output_frame = tk.Frame(self.root, bg="black", bd=2)
        output_frame.pack(fill="both", expand=True, padx=20, pady=5)
        
        self.output = scrolledtext.ScrolledText(output_frame, bg="#111", fg="#00FFAA", 
                                                font=("Consolas", 10), insertbackground="white")
        self.output.pack(fill="both", expand=True)

    # ================== LOGIC & THREADING ==================

    def log(self, text):
        """Thread-safe log method via Queue"""
        self.log_queue.put(text)

    def process_queue(self):
        """Checks the queue and updates GUI from the Main Thread"""
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.output.insert(tk.END, str(msg) + "\n")
                self.output.see(tk.END)
                self.results_data.append(str(msg))
        except queue.Empty:
            pass
        # Schedule next check
        self.root.after(100, self.process_queue)

    def toggle_buttons(self, state):
        """Enable or disable buttons during scan"""
        st = tk.NORMAL if state else tk.DISABLED
        self.btn_scan.config(state=st)
        self.btn_net_scan.config(state=st)
        self.btn_sel_scan.config(state=st)
        self.btn_save.config(state=st)
        self.btn_summary.config(state=st) # Disable summary during scan

    def set_scanning(self, is_scanning):
        self.scanning = is_scanning
        self.toggle_buttons(not is_scanning)
        if is_scanning:
            self.status_var.set("Status: Scanning...")
            self.root.config(cursor="watch")
        else:
            self.status_var.set("Status: Idle")
            self.root.config(cursor="")

    # ================== ACTIONS ==================

    def fill_my_ip(self):
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, self.local_ip)

    def on_device_select(self, event):
        selection = self.device_listbox.curselection()
        if selection:
            # devices list stores dictionaries now
            device = self.devices[selection[0]]
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, device['ip'])

    def start_scan_thread(self):
        if not self.scanning:
            threading.Thread(target=self.start_scan, daemon=True).start()

    def start_scan(self):
        target = self.ip_entry.get().strip()
        port_range = self.port_entry.get().strip()
        scan_type = self.scan_type.get()

        if not target:
            self.log("⚠️ Error: Please enter a Target IP.")
            return

        self.set_scanning(True)
        self.output.delete(1.0, tk.END)
        self.results_data.clear()
        self.log(f"🚀 Starting {scan_type} on {target}...")

        results = run_scan(target, port_range, scan_type)

        for line in results:
            self.log(line)
        
        self.log("✅ Scan Finished.")
        self.set_scanning(False)

    def scan_network_thread(self):
        if not self.scanning:
            threading.Thread(target=self.scan_network, daemon=True).start()

    def scan_network(self):
        self.set_scanning(True)
        self.output.delete(1.0, tk.END)
        self.results_data.clear()
        self.devices.clear()
        self.device_listbox.delete(0, tk.END)

        net = get_network_range(self.local_ip)
        self.log(f"🔍 Discovering hosts on {net}...")

        # Use the new discover_hosts function
        devices = discover_hosts(net)

        if isinstance(devices, list) and len(devices) > 0 and isinstance(devices[0], str):
            # It's an error list
            for err in devices:
                self.log(err)
        else:
            # It's a list of device dicts
            if not devices:
                self.log("⚠️ No devices found.")
            else:
                for dev in devices:
                    self.devices.append(dev)
                    display_text = f"{dev['ip']} ({dev['hostname']})"
                    self.device_listbox.insert(tk.END, display_text)
                    
                    self.log("-" * 30)
                    self.log(f"Host: {dev['ip']}")
                    self.log(f"Hostname: {dev['hostname']}")
                    self.log(f"State: {dev['state']}")
        
        self.log("✅ Network Discovery Complete.")
        self.set_scanning(False)

    def scan_selected_device_thread(self):
        if not self.scanning:
            threading.Thread(target=self.scan_selected_device, daemon=True).start()

    def scan_selected_device(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Select a device or enter an IP first.")
            return

        self.output.delete(1.0, tk.END)
        self.results_data.clear()
        
        # Start the detailed scan
        self.start_scan()

    def save_results(self):
        if not self.results_data:
            messagebox.showinfo("Info", "No results to save.")
            return
            
        success = save_to_file(self.results_data, parent_window=self.root)
        if success:
            messagebox.showinfo("Success", "Results saved successfully!")
        else:
            messagebox.showerror("Error", "Failed to save results.")

    def show_summary_popup(self):
        """Opens a popup window with the scan summary."""
        if not self.results_data:
            messagebox.showwarning("No Data", "No scan results available to summarize.")
            return

        # Generate the summary text
        summary_text = generate_summary(self.results_data)

        # Create a new popup window (Toplevel)
        popup = tk.Toplevel(self.root)
        popup.title("Scan Summary")
        popup.geometry("500x450")
        popup.configure(bg="#2b2b2b")
        popup.transient(self.root) # Set to be on top of the main window
        popup.grab_set() # Make it modal (click outside does nothing)

        # Title Label
        tk.Label(popup, text="Scan Analysis Report", 
                 font=("Helvetica", 16, "bold"), 
                 fg="#00FFAA", bg="#2b2b2b").pack(pady=15)

        # Text Area for the summary
        txt = tk.Text(popup, height=15, width=60, bg="#111", fg="white", 
                      font=("Consolas", 10), relief="flat", padx=10, pady=10)
        txt.pack(padx=20, pady=10)
        txt.insert(tk.END, summary_text)
        txt.config(state="disabled") # Make it read-only

        # Close Button
        tk.Button(popup, text="Close", command=popup.destroy, 
                  bg="#444", fg="white", width=10).pack(pady=10)

    def run(self):
        self.root.mainloop()