# 🛡️ Recon_Toolkit

**A Modular Python Security Assessment & Reconnaissance Suite**

`Recon_Toolkit` is a unified, command-line offensive security utility designed to streamline the initial phases of penetration testing. It integrates network reconnaissance, web application discovery, credential auditing, and asset retrieval into a single, interactive menu-driven application.

Designed for security professionals, students, and CTF players, it leverages standard Python libraries (`socket`, `requests`, `paramiko`, `hashlib`) to execute complex scans without requiring a fragmented set of CLI dependencies.

> ⚠️ **Educational Use Only:** This project is intended for authorized cybersecurity labs, personal testing environments, and educational purposes. Do not use it against systems or networks without explicit permission.

---

## 📌 Features

The toolkit includes six core modules accessible via an interactive menu:

| Module | Description |
| :--- | :--- |
| **1. Subdomain Enumeration** | Discovers active subdomains of a target domain using custom wordlists, filtering out non-responsive hosts. |
| **2. Directory Busting** | Identifies valid paths, hidden files, and admin panels on web servers. Supports custom extensions and filters 404s. |
| **3. TCP Port Scanner** | Performs sequential scans of target IP ranges (1-65535) and maps open ports to common services (SSH, HTTP, SMB). |
| **4. Hash Cracker** | Performs offline brute-force attacks on hashed data. Supports MD5, SHA-1, SHA-256, and SHA-512. |
| **5. SSH Brute Force** | Automates SSH authentication attempts against a target host using wordlists to identify weak credentials. |
| **6. File Downloader** | Retrieves assets from a target environment. Supports single-file downloads or batch processing from a URL list. |

### 💡 Technical Highlights
*   **Modular Architecture**: Core logic is separated from user interaction, making the code easy to test, extend, and maintain.
*   **Robust Error Handling**: Gracefully manages network timeouts, DNS resolution failures, file I/O errors, and invalid inputs.
*   **Cross-Platform**: Uses `pathlib` for consistent file path handling across Windows, macOS, and Linux.
*   **Zero-Config CLI**: Runs entirely from a single Python script with no complex configuration files required.

---

## 🏗️ Project Structure

```text
Recon_Toolkit/
│
├── recon_toolkit.py    # Main application logic
├── wordlists/          # (Optional) Directory for local wordlists
│   ├── subdomains.txt  # Common subdomains (www, mail, dev, etc.)
│   ├── common.txt      # Common web directories
│   └── rockyou.txt     # Top 1000 passwords (sample)
├── downloads/          # (Auto-generated) Directory for downloaded assets
└── README.md           # Project documentation
```

---

## 🔄 How It Works

`Recon_Toolkit` operates as a stateful interactive loop. The user selects a module, provides target parameters, and the toolkit executes the corresponding core functions.

### 🖥️ Execution Flow
1.  **Menu Selection**: The user chooses a tool (1-6) from the main menu.
2.  **Input Validation**: The toolkit validates URLs, IP addresses, port ranges, and file paths before execution.
3.  **Execution**: The selected core function runs (e.g., `scan_ports`, `crack_hash`).
4.  **Output**: Real-time findings are printed to the console, followed by a summary report.

### 🔗 Logic Flow
```text
        ┌─────────────────┐
        │     User CLI    │
        │   (Selection)   │
        └────────┬────────┘
                 │
                 │ Input Params
                 ▼
        ┌─────────────────┐
        │  Core Logic     │
        │  (Functions)    │
        └────────┬────────┘
                 │
                 │ Network / File I/O
                 ▼
        ┌─────────────────┐
        │    Target       │
        │  (Environment)  │
        └─────────────────┘
```

---

## ⚙️ Requirements

*   **Python 3.8+**
*   **Dependencies**:
    *   `requests`: For HTTP/HTTPS interactions.
    *   `paramiko`: For SSH client operations.
*   **Wordlists**: Local text files for subdomains, directories, passwords, and hashes.

---

## 🚀 Setup

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/Recon_Toolkit.git
cd Recon_Toolkit
```

### 2. Install Dependencies
```bash
pip install requests paramiko
```

### 3. Prepare Wordlists
Ensure you have local text files ready for use. Recommended sources:
*   **SecLists**: For subdomains and directory busting.
*   **RockYou**: For password brute-forcing.
*   **Custom**: For specific hash targets.

---

## ▶️ Running the Project

Start the toolkit:
```bash
python3 recon_toolkit.py
```

You will see the main menu:
```text
========================================
      Recon_Toolkit
========================================
  1. Subdomain Enumeration
  2. Directory Enumeration
  3. Port Scan
  4. Hash Cracker
  5. SSH Brute Force
  6. File Downloader
  7. Exit
========================================
```

### 📝 Example Usage

#### 🔍 Port Scan
```text
Select an option: 3
Enter target IP or hostname: 192.168.1.10
Enter max port to scan (default: 1024): 1024

[*] Scanning 192.168.1.10 (ports 1-1024)...

Port      Likely Service
------------------------------
22        SSH
80        HTTP
```

#### 🔓 Hash Cracker
```text
Select an option: 4
Enter target hash: 5f4dcc3b5aa765d61d8327deb882cf99
Enter wordlist path: wordlists/rockyou.txt
Enter algorithm (default: md5): md5

[*] Checking wordlist...

[+] Match found at line 12!
[+] Plaintext: password
[*] Candidates checked: 12
```

#### 📥 File Downloader
```text
Select an option: 6
Enter URL or path to URL list file: http://192.168.1.10/backup.zip

[*] Downloading http://192.168.1.10/backup.zip...
[+] Downloaded: backup.zip (102400 bytes)
```

---

## 🧠 Concepts Demonstrated

This project is useful for learning:
*   **Socket Programming**: TCP connection handling and port scanning.
*   **HTTP Protocol**: Status code analysis, redirect handling, and content retrieval.
*   **Cryptography**: Hashing algorithms (MD5, SHA-1, SHA-256) and brute-force verification.
*   **SSH Protocol**: Client-side authentication and key exchange basics.
*   **File I/O**: Efficient wordlist processing and file downloading.
*   **Error Handling**: Managing network instability and invalid user inputs in a production-like environment.

---

## 🔐 Cybersecurity Context

`Recon_Toolkit` is a small educational implementation that helps demonstrate the networking principles behind offensive security tools.

It can be used in an isolated cybersecurity lab to understand how an attacker might map a network, discover web vulnerabilities, and test credential strength.

It does not implement advanced evasion techniques, persistence mechanisms, or zero-day exploit logic. It focuses on the fundamental "reconnaissance to exploitation" workflow.

> ⚠️ **Disclaimer**
> This project is created strictly for educational and authorized security-testing purposes.
>
> Only run `Recon_Toolkit` on:
> *   Systems you own
> *   Your own virtual machines (e.g., Vagrant, VirtualBox)
> *   Authorized penetration-testing environments
> *   Cybersecurity training labs such as HackTheBox, TryHackMe, or CTF environments
>
> Do not use this project to access, control, or communicate with systems without explicit authorization.

---

## 👨‍💻 Author

**Sahil Chauhan**
*Cybersecurity / Red Team Learning Project*

---

## ⭐ Future Improvements

Possible future learning extensions include:
*   **Threading**: Parallelizing port scans and brute-force attacks for speed.
*   **TLS Inspection**: Analyzing SSL/TLS certificates on the target.
*   **Vulnerability Scanning**: Integrating checks for known CVEs.
*   **Report Generation**: Exporting results to HTML or PDF.
*   **GUI Interface**: Wrapping the CLI in a Tkinter or Web-based dashboard.
*   **Proxy Support**: Routing traffic through TOR or HTTP proxies.

---

## 📜 License

This project is provided for educational and research purposes. Use responsibly and only in environments where you have permission.
