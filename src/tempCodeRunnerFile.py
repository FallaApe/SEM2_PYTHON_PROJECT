import sys
import os

# Add current folder to Python path so it can find 'gui' and 'scanner'
sys.path.insert(0, os.getcwd())

print("Starting Application...")

try:
    # Try to import the GUI
    from gui.app_gui import NetworkScannerGUI
    
    # Create the app
    app = NetworkScannerGUI()
    
    # Check if the window was created (it might fail if Nmap is missing)
    if app.root.winfo_exists():
        print("GUI Window created successfully.")
        app.run()
    else:
        print("ERROR: The application closed immediately.")
        print("REASON: Nmap software is likely not installed on your computer.")

except ImportError as e:
    print(f"IMPORT ERROR: {e}")
    print("SOLUTION: Check that 'gui/', 'scanner/', and 'utils/' folders exist in the same directory.")
    print("SOLUTION: Run 'pip install python-nmap' in your terminal.")

except Exception as e:
    print(f"CRITICAL ERROR: {e}")
    import traceback
    traceback.print_exc()