import tkinter as tk
from tkinter import messagebox
from scanner.nmap_scanner import run_scan
from utils.file_handler import save_results

scan_output = ""

def start_scan():
    global scan_output

    ip = ip_entry.get()
    ports = port_entry.get()

    if not ip or not ports:
        messagebox.showerror("Error", "Please enter IP and Port range")
        return

    result_box.delete(1.0, tk.END)

    result = run_scan(ip, ports)

    scan_output = result

    result_box.insert(tk.END, result)


def save_scan():
    global scan_output

    if not scan_output:
        messagebox.showerror("Error", "No scan results to save")
        return

    message = save_results(scan_output)

    messagebox.showinfo("Save", message)


def start_gui():
    window = tk.Tk()
    window.title("Python Network Scanner")
    window.geometry("600x400")

    global ip_entry
    global port_entry
    global result_box

    tk.Label(window, text="Target IP").pack()

    ip_entry = tk.Entry(window, width=30)
    ip_entry.pack()

    tk.Label(window, text="Port Range (example: 1-1000)").pack()

    port_entry = tk.Entry(window, width=30)
    port_entry.pack()

    tk.Button(window, text="Start Scan", command=start_scan).pack(pady=10)

    result_box = tk.Text(window, height=15, width=70)
    result_box.pack()

    tk.Button(window, text="Save Results", command=save_scan).pack(pady=5)

    window.mainloop()
