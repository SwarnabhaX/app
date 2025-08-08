# Web-Based Network Port Scanner

This project is a web-based network port scanner built with Python, Flask, and Scapy. It provides a user-friendly interface to scan hosts for open ports using various methods.

## Features

- **Multiple Scan Types:** Supports both standard TCP Connect scans and stealthier SYN (half-open) scans.
- **Flexible Target Specification:** Scan single hosts, lists of hosts (comma or newline-separated), and entire subnets using CIDR notation (e.g., `192.168.1.0/24`).
- **Customizable Port Selection:** Scan single ports, comma-separated lists of ports, and port ranges (e.g., `1-1024`).
- **Concurrent Scanning:** Uses a configurable number of threads to scan multiple ports and hosts in parallel for high performance.
- **Configurable Parameters:** Adjust the connection timeout and concurrency level directly from the web UI.
- **User-Friendly Interface:** All features are accessible through a simple and intuitive web interface.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    The required Python packages are listed in `requirements.txt`. Install them using pip:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Run the Flask application:**
    ```bash
    python3 app.py
    ```

2.  **For SYN Scans (Root Privileges Required):**
    The SYN scan (half-open scan) requires raw socket permissions, which are typically only available to the root user. To use the SYN scan feature, you must run the application with `sudo`:
    ```bash
    sudo python3 app.py
    ```
    If you select the SYN scan option without running as root, the application will flash a warning and automatically fall back to a standard TCP Connect scan.

3.  **Access the Web Interface:**
    Once the server is running, open your web browser and navigate to:
    ```
    http://127.0.0.1:5000
    ```

4.  **Perform a Scan:**
    - Enter the target host(s) and port(s) in the respective fields.
    - Adjust the timeout and concurrency settings if needed.
    - Select the desired scan type.
    - Click "Scan" to begin.
