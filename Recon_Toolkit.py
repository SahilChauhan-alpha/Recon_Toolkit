import requests
import socket
import hashlib
import paramiko
import os
from pathlib import Path
from urllib.parse import urlparse


# ----- Core Logic Functions -----


def load_wordlist(filepath):
    """Read a wordlist and return stripped, non-empty lines."""
    path = Path(filepath).expanduser()

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as file:
            words = [line.strip() for line in file if line.strip()]

        print(f"[*] Loaded {len(words)} entries from {path}")
        return words

    except FileNotFoundError:
        print(f"[!] Wordlist not found: {path}")
    except PermissionError:
        print(f"[!] Permission denied: {path}")
    except OSError as error:
        print(f"[!] Could not read wordlist: {error}")

    return []


def enumerate_subdomains(domain, wordlist):
    """Enumerate subdomains on an authorized target."""
    found = []

    domain = domain.strip().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0]

    for sub in wordlist:
        url = f"http://{sub}.{domain}"

        try:
            response = requests.get(url, timeout=3)
            print(f"[+] Responded ({response.status_code}): {url}")
            found.append(url)
        except requests.RequestException:
            pass

    return found


def enumerate_directories(target_url, wordlist, extension=".html"):
    """Check candidate paths on an authorized target."""
    found = []
    target_url = target_url.rstrip("/")
    extension = extension.strip()

    for entry in wordlist:
        url = f"{target_url}/{entry}{extension}"

        try:
            response = requests.get(url, timeout=3, allow_redirects=False)

            if response.status_code != 404:
                print(f"[+] {response.status_code} - {url}")
                found.append(url)

        except requests.RequestException:
            pass

    return found


def resolve_target(target):
    """Resolve a hostname to an IP address."""
    try:
        ip = socket.gethostbyname(target)

        if ip != target:
            print(f"[*] Resolved {target} to {ip}")

        return ip

    except socket.gaierror:
        print(f"[!] Could not resolve {target}")
        return None


def probe_port(ip, port, timeout=0.5):
    """Check whether a TCP port accepts connections."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0

    except OSError:
        return False


def scan_ports(ip, port_range, timeout=0.5):
    """Scan a range of TCP ports on an authorized target."""
    open_ports = []

    for port in port_range:
        if probe_port(ip, port, timeout):
            print(f"[+] Port {port} is open")
            open_ports.append(port)

    return open_ports


def compute_hash(text, algorithm="md5"):
    """Compute a hash using a supported hashlib algorithm."""
    try:
        return hashlib.new(algorithm.lower(), text.encode("utf-8")).hexdigest()

    except ValueError:
        return None


def crack_hash(target_hash, wordlist_path, algorithm="md5"):
    """Check wordlist candidates against a target hash."""
    path = Path(wordlist_path).expanduser()
    algorithm = algorithm.strip().lower()
    target_hash = target_hash.strip().lower()

    if not path.is_file():
        print(f"[!] Wordlist file not found: {path}")
        return None

    try:
        hashlib.new(algorithm)
    except ValueError:
        print(f"[!] Unsupported hash algorithm: {algorithm}")
        print("[*] Check hashlib.algorithms_available.")
        return None

    attempts = 0

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as file:
            for line_number, line in enumerate(file, start=1):
                candidate = line.strip()

                if not candidate:
                    continue

                attempts += 1
                candidate_hash = compute_hash(candidate, algorithm)

                if candidate_hash == target_hash:
                    print(f"[+] Match found at line {line_number}!")
                    print(f"[+] Plaintext: {candidate}")
                    print(f"[*] Candidates checked: {attempts}")
                    return candidate

        print(f"[*] Candidates checked: {attempts}")
        print("[-] Wordlist exhausted. No match found.")
        print("[*] Verify the hash, algorithm, and wordlist.")

    except PermissionError:
        print(f"[!] Permission denied: {path}")
    except OSError as error:
        print(f"[!] Could not read wordlist: {error}")

    return None


def try_credential(target, username, password, port=22):
    """Attempt SSH login with the given credentials. Return True on success."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(target, port=port, username=username, password=password, timeout=5)
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, OSError) as e:
        print(f"[!] Connection error: {e}")
        return False


def brute_force_ssh(target, username, wordlist_path, port=22):
    """Try each password in the wordlist against the target SSH server."""
    path = Path(wordlist_path).expanduser()

    if not path.is_file():
        print(f"[!] Wordlist not found: {path}")
        return None

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading wordlist: {e}")
        return None

    print(f"[*] Loaded {len(passwords)} password(s) from {path}")
    print(f"[*] Target: {target}:{port}")
    print(f"[*] Username: {username}\n")

    for attempt, password in enumerate(passwords, start=1):
        print(f"[*] Attempt {attempt}/{len(passwords)}: {password}")

        if try_credential(target, username, password, port):
            print(f"\n[+] Password found: {password}")
            return password

    print(f"\n[-] Exhausted wordlist. No valid password found.")
    return None


def download_file(url, output_path):
    """Download a file from a URL and save it locally."""
    try:
        r = requests.get(url, allow_redirects=True, timeout=10)
        r.raise_for_status()

        with open(output_path, "wb") as f:
            f.write(r.content)

        print(f"[+] Downloaded: {output_path} ({len(r.content)} bytes)")
        return True

    except requests.ConnectionError:
        print(f"[!] Connection failed: {url}")
        return False
    except requests.Timeout:
        print(f"[!] Request timed out: {url}")
        return False
    except requests.HTTPError as e:
        print(f"[!] HTTP error: {e}")
        return False


def download_from_list(url_list, output_dir="downloads"):
    """Download files from a list of URLs into the specified directory."""
    os.makedirs(output_dir, exist_ok=True)
    results = {"success": 0, "failed": 0}

    for url in url_list:
        filename = url.split("/")[-1]
        if not filename:
            filename = "index.html"
        output_path = os.path.join(output_dir, filename)

        if download_file(url, output_path):
            results["success"] += 1
        else:
            results["failed"] += 1

    print(
        f"\n[*] Complete: {results['success']} downloaded, {results['failed']} failed"
    )
    return results


# ----- Toolkit Menu Functions -----


def run_subdomain_enum():
    domain = input("Enter target domain: ").strip()
    wordlist_path = input("Enter wordlist path: ").strip()

    wordlist = load_wordlist(wordlist_path)
    if not wordlist:
        return

    results = enumerate_subdomains(domain, wordlist)
    print(f"\n[*] Found {len(results)} responding subdomain(s).")


def run_directory_enum():
    target_url = input("Enter target URL (e.g., http://127.0.0.1): ").strip()

    parsed = urlparse(target_url)

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("[!] Enter a valid HTTP or HTTPS URL.")
        return

    wordlist_path = input("Enter wordlist path: ").strip()
    extension = input("Enter file extension (default: .html): ").strip() or ".html"

    wordlist = load_wordlist(wordlist_path)
    if not wordlist:
        return

    results = enumerate_directories(target_url, wordlist, extension)

    print(f"\n[*] Found {len(results)} responding path(s).")


def run_port_scan():
    target = input("Enter target IP or hostname: ").strip()
    max_port_str = input("Enter max port to scan (default: 1024): ").strip() or "1024"

    try:
        max_port = int(max_port_str)

        if not 1 <= max_port <= 65535:
            raise ValueError

    except ValueError:
        print("[!] Enter a port between 1 and 65535.")
        return

    ip = resolve_target(target)
    if not ip:
        return

    print(f"\n[*] Scanning {ip} (ports 1-{max_port})...\n")
    open_ports = scan_ports(ip, range(1, max_port + 1))

    common_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP Proxy",
    }

    if open_ports:
        print(f"\n{'Port':<10}{'Likely Service':<20}")
        print("-" * 30)

        for port in sorted(open_ports):
            print(f"{port:<10}{common_services.get(port, 'Unknown'):<20}")
    else:
        print("[!] No open ports found.")


def run_hash_cracker():
    target_hash = input("Enter target hash: ").strip()
    wordlist_path = input("Enter wordlist path: ").strip()
    algorithm = input("Enter algorithm (default: md5): ").strip() or "md5"

    if not target_hash or not wordlist_path:
        print("[!] Both hash and wordlist are required.")
        return

    print(f"[*] Target hash: {target_hash}")
    print(f"[*] Algorithm:   {algorithm}")
    print(f"[*] Wordlist:    {Path(wordlist_path).expanduser()}")
    print("[*] Checking wordlist...\n")

    result = crack_hash(target_hash, wordlist_path, algorithm)

    if result is not None:
        print("\n[*] Hash checked successfully.")
    else:
        print("\n[*] No plaintext recovered.")


def run_ssh_bruteforce():
    target = input("Enter target IP or hostname: ").strip()
    username = input("Enter username: ").strip()
    wordlist_path = input("Enter wordlist path: ").strip()
    port_str = input("Enter SSH port (default: 22): ").strip() or "22"

    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("[!] Invalid port number.")
        return

    if not target or not username or not wordlist_path:
        print("[!] Target, username, and wordlist are required.")
        return

    print(f"[*] Starting SSH brute force on {target}:{port} as '{username}'...")

    result = brute_force_ssh(target, username, wordlist_path, port)

    if result:
        print(f"\n[*] Valid credentials: {username}:{result}")
        print(f"[*] Connect with: ssh {username}@{target}")
    else:
        print(f"\n[*] Try a larger wordlist or a different username.")


def run_downloader():
    """Download a single file or a list of files."""
    target = input("Enter URL or path to URL list file: ").strip()

    if not target:
        print("[!] No target specified.")
        return

    # If it's a local file, treat it as a list of URLs
    if os.path.isfile(target):
        try:
            with open(target, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(urls)} URL(s) from {target}")
            if urls:
                download_from_list(urls)
        except Exception as e:
            print(f"[!] Error reading file: {e}")
    else:
        # Otherwise, treat it as a single URL
        # Ensure it has a scheme
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"http://{target}"

        filename = target.split("/")[-1] or "downloaded_file"
        # Sanitize filename
        filename = os.path.basename(filename)
        if not filename:
            filename = "downloaded_file"

        print(f"[*] Downloading {target}...")
        download_file(target, filename)


def show_menu():
    print("\n" + "=" * 40)
    print("      Python Pentester Toolkit")
    print("=" * 40)
    print("  1. Subdomain Enumeration")
    print("  2. Directory Enumeration")
    print("  3. Port Scan")
    print("  4. Hash Cracker")
    print("  5. SSH Brute Force")
    print("  6. File Downloader")
    print("  7. Exit")
    print("=" * 40)


# ----- Main Loop -----


def main():
    actions = {
        "1": run_subdomain_enum,
        "2": run_directory_enum,
        "3": run_port_scan,
        "4": run_hash_cracker,
        "5": run_ssh_bruteforce,
        "6": run_downloader,
    }

    while True:
        show_menu()
        choice = input("\nSelect an option: ").strip()

        if choice == "7":
            print("[*] Exiting toolkit. Goodbye.")
            break

        action = actions.get(choice)

        if action:
            print()
            action()
        else:
            print("[!] Invalid option. Enter 1-7.")


if __name__ == "__main__":
    main()
