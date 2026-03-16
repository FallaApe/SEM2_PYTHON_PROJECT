def save_results(data, filename="scan_results.txt"):
    try:
        with open(filename, "w") as file:
            file.write(data)
        return "Results saved successfully."
    except Exception as e:
        return f"Error saving file: {e}"
