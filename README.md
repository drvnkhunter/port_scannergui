# Port Scanner and Basic Vulnerability Analyzer

This Python program is a multi-functional **port scanner** with a **graphical user interface (GUI)**, capable of identifying open ports on a specified IP address or hostname. In addition to port detection, it incorporates a simulated **"vulnerability analyzer"** feature. This functionality identifies common services on known ports and, based on that identification, offers **security suggestions** and recommended configurations (without performing any actual exploitation). It's ideal for educational purposes and for those looking to expand their offensive security or monitoring portfolio.

## Key Features

* **Multi-threaded Port Scanning**: Performs fast and efficient scans by utilizing threads to check multiple ports simultaneously.
* **Common Service Detection**: Identifies and names services associated with well-known ports (e.g., HTTP, SSH, FTP, etc.).
* **Simulated Vulnerability Analysis**: Provides basic security suggestions and potential vulnerabilities for detected services, based on an internal dictionary.
* **Intuitive Graphical Interface (GUI)**: Developed with Tkinter, it offers a simple user experience and clear, real-time visualization of results.
* **Input Validation**: Ensures that user-entered information (host, port range, number of threads) is valid.
* **Scan Control**: Allows users to start and stop the scanning process at any time.

## System Requirements

To run this application, you will need to have the following installed:

* **Python 3.x** (tested with 3.13.2, but should work with earlier Python 3 versions).
    * `Tkinter` comes included with the standard Python installation.
    * No additional external libraries are required.

## Installation and Usage

Follow these steps to get the Port Scanner up and running:

1.  **Clone the Repository:**
    Open your terminal or command line and execute:
    ```bash
    git clone [https://github.com/your_username/port_scannergui.git](https://github.com/your_username/port_scannergui.git)
    ```
    *(Replace `your_username` with your actual GitHub username.)*

2.  **Navigate to the Project Directory:**
    ```bash
    cd port_scannergui
    ```

3.  **Run the Application:**
    ```bash
    python port_scannergui.py
    ```
    *(If you have multiple Python versions, you might need to use `python3 port_scannergui.py`)*

## GUI Usage

1.  Enter the IP address or hostname to scan in the "Host a escanear" (Host to scan) field.
2.  Define the port range (start and end) you wish to scan.
3.  Set the number of threads to control the scan speed.
4.  Click "Iniciar Escaneo" (Start Scan) to begin.
5.  Results will be displayed in real-time in the lower text area.
6.  You can stop the scan at any time by clicking "Detener Escaneo" (Stop Scan).

## Code Structure

* **`COMMON_PORTS`**: Dictionary with common ports and their services.
* **`VULNERABILITY_SUGGESTIONS`**: Dictionary that simulates vulnerability suggestions based on detected services.
* **`PortScannerGUI`**: Main class managing the graphical interface and scanning logic.
    * `__init__`: Constructor setting up the GUI.
    * `log_message`: Inserts messages into the GUI output.
    * `port_scan`: Core function for port connection.
    * `simulate_vulnerability_analysis`: Generates security suggestions.
    * `worker`: Function executed by each thread to process ports from the queue.
    * `start_scan`: Validates inputs and launches the scanning process.
    * `check_scan_completion`: Monitors the scan status.
    * `finish_scan`: Completes the scan and re-enables the start button.
    * `stop_scan`: Halts a scan in progress.

## Author

* **[Francisco Daniel Jiménez Cunjamá]**
    * GitHub: [@drvnkhunter](https://github.com/drvnkhunter)
    * Linkedin [LinkedIn](https://www.linkedin.com/in/frandanielcunjama/)

---
