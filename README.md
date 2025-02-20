# ZMap - Basic Port Scanner Tool

ZMap is a simple and fast port scanning tool designed to identify open ports and detect common services running on a target IP address. It supports scanning specific ports or all ports (1-65535) and provides basic vulnerability checks for common services.

---

## Features

- **Fast Port Scanning**: Uses multi-threading to scan ports quickly.
- **Service Detection**: Identifies common services running on open ports.
- **Vulnerability Checks**: Provides basic vulnerability warnings for common services (e.g., FTP, SSH, HTTP).
- **Flexible Port Selection**: Scan specific ports (e.g., `21,53,80`) or all ports (`all`).

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/seu_usuario/zmap.git
   cd zmap

2. **Install dependencies:**

    Ensure you have Python 3.x installed.

    Install the required Python packages:
    bash
    Copy

    pip install colorama


**3. Make the script executable (**<span style="color:red;">_optional_</span>**):**
bash
Copy

chmod +x zmap.py