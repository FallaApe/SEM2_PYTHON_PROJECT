# # Python GUI Network Scanner

A simple GUI-based network scanner built using Python and Nmap.  
This tool allows users to scan a target IP address and port range through an easy-to-use graphical interface.

The project demonstrates basic networking concepts, Python programming, and integration with external tools.

---

## Features

- Scan any user-defined IP address
- Custom port range scanning
- Multiple scan options
- Simple graphical interface
- Displays open ports and services
- Save scan results to a file

---

## Technologies Used

- Python
- Tkinter (GUI)
- Nmap
- python-nmap

---

## Screenshots

### Application Interface
(Add screenshot here)

### Scan Results
(Add screenshot here)

### Example Scan Running
(Add screenshot here)

---

## Project Structure

network-scanner/

│

├── src/

│   ├── gui/

│   │   └── app_gui.py

│   │

│   ├── scanner/

│   │   └── nmap_scanner.py

│   │

│   ├── utils/

│   │   └── file_handler.py

│   │

│   └── main.py

│

├── docs/

├── assets/

├── results/

├── tests/

│

├── requirements.txt

├── README.md

├── LICENSE

└── .gitignore

---

## Installation

1. Clone the repository

git clone https://github.com/yourusername/network-scanner.git

2. Navigate to the project directory

cd network-scanner

3. Install required dependencies

pip install -r requirements.txt

4. Install Nmap if it is not already installed on your system.

---

## Usage

Run the program:

python src/main.py

Steps:

1. Enter the target IP address  
2. Enter the port range  
3. Select scan type  
4. Click **Start Scan**  
5. View results in the output window  

---

## Example Output

PORT     STATE SERVICE  
22/tcp   open  ssh  
80/tcp   open  http  
443/tcp  open  https  

---

## Future Improvements

- Network range scanning
- Export results to CSV
- Improved GUI design
- Scan progress indicator

---

## License

This project is licensed under the MIT License.
