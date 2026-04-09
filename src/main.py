import sys
from gui.app_gui import NetworkScannerGUI

if __name__ == "__main__":
    try:
        app = NetworkScannerGUI()
        # Check if the window was created (it might be destroyed if Nmap check fails in __init__)
        if app.root.winfo_exists(): 
            app.run()
    except KeyboardInterrupt:
        print("\nApplication closed by user.")
        sys.exit()
    except Exception as e:
        print(f"Fatal Error: {e}")
        sys.exit(1)