from tkinter import filedialog
import os

def save_to_file(data, parent_window=None):
    """
    Opens a dialog to ask the user where to save the file.
    """
    if not data:
        return False

    # Ask for filename
    filepath = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        initialfile="scan_results.txt",
        parent=parent_window
    )

    if not filepath:  # User cancelled
        return False

    try:
        with open(filepath, "w", encoding="utf-8") as file:
            for line in data:
                file.write(str(line) + "\n")
        return True
    except Exception as e:
        print(f"Error saving file: {e}")
        # Optionally show a message box here
        return False