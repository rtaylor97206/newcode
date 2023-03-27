import re
import ipaddress
import socket
import tkinter as tk
from tkinter import filedialog
import speedtest
import time
import os
import subprocess
import getpass
import datetime
import ssl
import socket
import nmap


# Define regular expression patterns to match IP addresses, subnet masks, default gateways, passwords, and ports
ip_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
subnet_regex = r"subnet\s+" + ip_regex + r"\s+" + ip_regex
default_gateway_regex = r"default-gateway\s+" + ip_regex
password_regex = r"password\s+(\S+)"
port_regex = r"ip\s+address\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(\d+)"
unauthorized_regex = r"(username|password)\s+(\S+)"
allowed_ports = [22, 80, 443]
common_passwords = []
host_range = []
BENCHMARK_FILE = "benchmark.txt"

def check_unauthorized_devices():
    # Get list of all devices currently connected to the network
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-n -sP')
    all_hosts = nm.all_hosts()

    # Get list of authorized MAC addresses
    authorized_macs = ['12:34:56:78:90:ab', 'de:ad:be:ef:ca:fe']

    # Check for unauthorized MAC addresses
    for host in all_hosts:
        if 'mac' in nm[host]['addresses']:
            mac = nm[host]['addresses']['mac']
            if mac not in authorized_macs:
                print(f"Unauthorized device detected! MAC address: {mac}, IP address: {host}")

def check_port_security_violations():
    # Get list of all open ports on the device
    output = subprocess.check_output(["netstat", "-an"])
    open_ports = set(line.split()[1].split(':')[-1] for line in output.decode('utf-8').split('\n')[2:] if line.strip() != '')

    # Get list of authorized ports
    authorized_ports = ['22', '80', '443']

    # Check for unauthorized ports
    for port in open_ports:
        if port not in authorized_ports:
            print(f"Port security violation detected! Port: {port}")

def check_dns_spoofing():
    # Get current DNS server IP address
    output = subprocess.check_output(["nslookup", "google.com"])
    dns_server = output.decode('utf-8').split(' ')[-1].strip()

    # Check for DNS spoofing
    if dns_server != '8.8.8.8':
        print(f"DNS spoofing detected! Current DNS server: {dns_server}")



def network_monitor():
    st = speedtest.Speedtest()
    benchmark_speed = None
    local_ip = None
    default_path = os.path.join(os.path.expanduser("~"), "Downloads")
    BENCHMARK_FILE = os.path.join(default_path, "speedtest.benchmark")

    if os.path.isfile(BENCHMARK_FILE):
        print(f"Benchmark file found at {BENCHMARK_FILE}")
    else:
        print(f"No benchmark file found at {BENCHMARK_FILE}")
        path = input("Enter the path where you would like to store the benchmark file (press Enter to use default path): ")
        if path.strip():
            BENCHMARK_FILE = os.path.join(path, "speedtest.benchmark")
        print(f"Benchmark file will be stored at {BENCHMARK_FILE}")

    while True:
        print("1. Check current network speed")
        print("2. Benchmark network speed")
        print("3. Compare current speed to benchmark")
        print("4. Exit")

        if benchmark_speed is None:
            print("No benchmark speed set")
        else:
            print(f"Benchmark speed: {benchmark_speed / 1_000_000:.2f} Mbps")

        choice = input("Enter choice (1/2/3/4): ")

        if choice == "1":
            download_speed = st.download()
            print(f"Current download speed: {download_speed / 1_000_000:.2f} Mbps")
        elif choice == "2":
            print("Running benchmark...")
            speeds = []
            for i in range(5):
                speed = st.download()
                speeds.append(speed)
                time.sleep(6)
            benchmark_speed = sum(speeds) / len(speeds)
            with open(BENCHMARK_FILE, "w") as f:
                f.write(str(benchmark_speed))
            print(f"Benchmark speed set to: {benchmark_speed / 1_000_000:.2f} Mbps")
        elif choice == "3":
            if benchmark_speed is None:
                print("You need to run a benchmark first!")
            else:
                current_speed = st.download()
                speed_diff = benchmark_speed - current_speed
                if speed_diff < 0:
                    print(f"Your speed decreased by {-speed_diff / 1_000_000:.2f} Mbps since the benchmark")
                elif speed_diff > 0:
                    print(f"Your speed increased by {speed_diff / 1_000_000:.2f} Mbps since the benchmark")
                else:
                    print("Your speed has not changed since the benchmark")
        elif choice == "4":
            break
        else:
            print("Invalid choice. Try again.")

def check_firewall_status():
    try:
        firewall_status = subprocess.check_output(['netsh', 'advfirewall', 'show', 'allprofiles', 'state']).decode()
        if "ON" in firewall_status:
            status = "Firewall is ON"
        else:
            status = "Firewall is OFF"
    except:
        status = "Error: Could not check firewall status"
    print(status)
    return status

def scan_ports(host, port_list):
    open_ports = []
    for port in port_list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports
            
def get_device_info():
    """Gets the device name and IP address.

    Returns:
        Tuple[str, str]: The device name and IP address.
    """
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return hostname, ip_address

def get_backup_dir():
    """Prompts for the backup directory.

    Returns:
        str: The backup directory.
    """
    backup_dir = input("Enter the backup directory: ")
    return backup_dir

def backup_configuration(configuration):
    """Backs up a device configuration to a file with the device name and timestamp.

    Args:
        configuration (str): The device configuration to back up.

    Returns:
        str: The path of the backup file.
    """
    # Get the device name and IP address
    device_name, ip_address = get_device_info()

    # Prompt for the backup directory
    backup_dir = get_backup_dir()

    # Create a directory for backups if it doesn't already exist
    os.makedirs(backup_dir, exist_ok=True)

    # Save the configuration to a file with the device name and timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{device_name}_{timestamp}.txt"
    filepath = os.path.join(backup_dir, filename)
    with open(filepath, "w") as f:
        f.write(configuration)

    return filepath


def compare_configurations(config1, config2):
    # Compare the configurations and return True if they are the same, False otherwise
    return config1 == config2


def manage_device_inventory(device_name, device_info):
    # Create a directory for inventory if it doesn't already exist
    if not os.path.exists(inventory_dir):
        os.makedirs(inventory_dir)
    
    # Save the device information to a file with the device name and timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = "{device_name}_{timestamp}.txt"
    inventory_path = os.path.join(inventory_dir, filename)
    
    with open(inventory_path, "w") as f:
        for key, value in device_info.items():
            f.write("{key}: {value}\n")
    
    print("Device inventory for {device_name} saved to {inventory_path}")
    
    return inventory_path

def scan_ports(host, port_list):
    open_ports = []
    for port in port_list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

    local_ip = input("Enter your local IP address: ")
    subnet_mask = input("Enter your subnet mask (e.g. 24): ")


def match_ip_address(string):
    ip_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    return re.findall(ip_regex, string)

def match_subnet(string):
    ip_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    subnet_regex = r"subnet\s+" + ip_regex + r"\s+" + ip_regex
    return re.findall(subnet_regex, string)

def match_default_gateway(string):
    ip_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    default_gateway_regex = r"default-gateway\s+" + ip_regex
    return re.findall(default_gateway_regex, string)

def match_password(string):
    password_regex = r"password\s+(\S+)"
    return re.findall(password_regex, string)

def match_port(string):
    port_regex = r"ip\s+address\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(\d+)"
    return re.findall(port_regex, string)

def match_unauthorized(string):
    unauthorized_regex = r"(username|password)\s+(\S+)"
    return re.findall(unauthorized_regex, string)





    

# Calculate the network address and host range based on the local IP and subnet mask
    network_address = str(ipaddress.IPv4Network("{local_ip}/{subnet_mask}").network_address)
    host_range = list(ipaddress.IPv4Network("{local_ip}/{subnet_mask}").hosts())

# Remove the network and broadcast addresses from the list of hosts
    host_range.pop(0)
    host_range.pop()


# Scan the ports on each host in the host range
for host in host_range:
    open_ports = scan_ports(str(host), [22, 80, 443])
    if open_ports:
        print("{host} has the following open ports: {open_ports}")
        
# Function to check for duplicate IP addresses
def check_duplicate_ip_addresses(config_text):
    ip_addresses = re.findall(ip_regex, config_text)
    duplicates = set([x for x in ip_addresses if ip_addresses.count(x) > 1])
    if duplicates:
        print("Duplicate IP addresses found:")
        for ip in duplicates:
            print(ip)

# Function to check for incorrect subnet masks
def check_subnet_masks(config_text):
    subnet_matches = re.findall(subnet_regex, config_text)
    for subnet_match in subnet_matches:
        network_address = subnet_match.split()[1]
        subnet_mask = subnet_match.split()[2]
        ip_network = ipaddress.IPv4Network("{network_address}/{subnet_mask}")
        if not ip_network.is_private:
            num_hosts = ip_network.num_addresses - 2
            if num_hosts != (1 << (32 - int(subnet_mask))):
                print("Incorrect subnet mask: {subnet_match}")

# Function to check for incorrect default gateways
def check_default_gateways(config_text):
    ip_addresses = re.findall(ip_regex, config_text)
    default_gateway_matches = re.findall(default_gateway_regex, config_text)
    for default_gateway_match in default_gateway_matches:
        default_gateway = default_gateway_match.split()[1]
        default_gateway_network = ipaddress.IPv4Address(default_gateway)
        if not any([ipaddress.IPv4Address(ip) in default_gateway_network.network_address for ip in ip_addresses]):
            print("Incorrect default gateway: {default_gateway_match}")

# Function to check for weak passwords
def check_weak_passwords(config_text):
    passwords = re.findall(password_regex, config_text)
    for password in passwords:
        if password in common_passwords or password == password[::-1] or password.isnumeric():
            print("Weak password found: {password}")

# Function to check for open ports
def check_open_ports(config_text):
    ports = set()
    for match in re.findall(port_regex, config_text):
        ports.add(int(match))
    open_ports = [port for port in ports if port not in allowed_ports]
    if open_ports:
        print("Open ports found:")
        for port in open_ports:
            print(port)

# Function to check for unauthorized access
def check_unauthorized_access(config_text):
    unauthorized_matches = re.findall(unauthorized_regex, config_text)
    if unauthorized_matches:
        print("Unauthorized access found:")
        for match in unauthorized_matches:
            print(match)

# Function to check SNMP security
def check_snmp_security(config_text):
    snmp_community_regex = r"snmp-server\s+community\s+(\S+)"
    snmp_communities = re.findall(snmp_community_regex, config_text)
    for snmp_community in snmp_communities:
        if snmp_community == "public":
            print("SNMP community 'public' found. Change to a more secure community string.")


            # Define a function to run all checks on the provided configuration text
def run_all_checks(config_text):
    check_duplicate_ip_addresses(config_text)
    check_subnet_masks(config_text)
    check_default_gateways(config_text)
    check_weak_passwords(config_text)
    check_open_ports(config_text)
    check_unauthorized_access(config_text)
    check_snmp_security(config_text)

def check_scan_vulnerabilities(host):
    # Define a list of known vulnerable ports
    vulnerable_ports = [21, 22, 23, 25, 53, 79, 80, 110, 111, 113, 123, 137, 139, 143, 161, 389, 443, 445, 512, 513, 514, 515, 873, 993, 995, 1080, 1099, 1433, 1521, 2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389, 5432, 5800, 5900, 5984, 6379, 7001, 7002, 8000, 8001, 8080, 8081, 8443, 8888, 9090, 9200, 9300, 11211, 27017, 27018, 27019]
    
    # Scan the host for open ports
    open_ports = scan_ports(host, vulnerable_ports)
    
    # Print any vulnerable ports that are open
    if len(open_ports) > 0:
        print(f"{host} is vulnerable to the following ports: {', '.join(map(str, open_ports))}")
    else:
        print(f"{host} is not vulnerable to any known ports.")

def check_ssl_tls_vulnerabilities():
    hostname = input("Enter the hostname to check: ")
    port = input("Enter the port to check: ")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    print("No certificate found.")
                else:
                    if 'subjectAltName' in cert:
                        for san in cert['subjectAltName']:
                            if san[0] == 'DNS' and san[1] != hostname:
                                print("Warning: Certificate subjectAltName doesn't match hostname")
                    if 'issuer' in cert and 'O' in cert['issuer']:
                        if 'RootCA' in cert['issuer']['O']:
                            print("Warning: Certificate is signed by a root CA.")
                    protocol_version = ssock.version()
                    if protocol_version == ssl.PROTOCOL_SSLv23:
                        print("Warning: Insecure SSLv2 or SSLv3 protocol in use.")
                    elif protocol_version == ssl.PROTOCOL_TLSv1:
                        print("Warning: Insecure TLSv1.0 protocol in use.")
    except Exception as e:
        print(f"Error: {e}")



# Define a function to present a menu of available functions and execute the selected function
def menu():
    root = tk.Tk()
    root.withdraw()

    open_file = input("Would you like to open a file? (y/n): ")

    if open_file.lower() == 'y':
        file_path = filedialog.askopenfilename()
        print(file_path)
        with open(file_path, "r") as f:
            config_text = f.read()
    
    while True:
        print("\nMenu:")
        print("1. Check Individual Processes")
        print("2. Run all Checks")
        print("3. Backup configuration")
        print("4. Inventory management")
        print("5. Change log management")
        print("6. Network performance monitoring")
        print("7. Security Checks")
        print("8. Exit")

        choice = input("Enter your choice (1-8): ")

        if choice == "1":
            while True:
                print("\nCheck Individual Processes:")
                print("1. Check for duplicate IP addresses")
                print("2. Check for incorrect subnet masks")
                print("3. Check for incorrect default gateways")
                print("4. Check for weak passwords")
                print("5. Check for open ports")
                print("6. Check for unauthorized access")
                print("7. Check SNMP security")
                print("8. Check for port vulnerability")
                print("9. Check Firewall Status")
                print("10. Back")

                check_choice = input("Enter your choice (1-10): ")

                if check_choice == "1":
                    check_duplicate_ip_addresses(config_text)
                elif check_choice == "2":
                    check_subnet_masks(config_text)
                elif check_choice == "3":
                    check_default_gateways(config_text)
                elif check_choice == "4":
                    check_weak_passwords(config_text)
                elif check_choice == "5":
                    check_open_ports(config_text)
                elif check_choice == "6":
                    check_unauthorized_access(config_text)
                elif check_choice == "7":
                    check_snmp_security(config_text)
                elif check_choice == "8":
                    check_scan_vulnerabilities(host='127.0.0.1')
                elif check_choice == "9":
                    check_firewall_status()
                elif check_choice == "10":
                    break
                else:
                    print("Invalid choice. Please try again.")
        elif choice == "2":
            check_duplicate_ip_addresses(config_text)
            check_subnet_masks(config_text)
            check_default_gateways(config_text)
            check_weak_passwords(config_text)
            check_open_ports(config_text)
            check_unauthorized_access(config_text)
            check_snmp_security(config_text)
            check_scan_vulnerabilities(host='127.0.0.1')
            check_firewall_status()
        elif choice == "3":
            backup_configuration(device_name, configuration, backup_dir)
        elif choice == "4":
            inventory_management()
        elif choice == "5":
            change_log_management()
        elif choice == "6":
            benchmark_speed = network_monitor()
        elif choice == "7":
            while True:
                print("\nSecurity Checks:")
                print("1. Check antivirus status")
                print("2. Check system updates")
                print("3. Check network security")
                print("4. Check system logs")
                print("5. Back")
                security_choice = input("Enter your choice (1-5): ")
        
        if security_choice == "1":
            check_antivirus_status()
        elif security_choice == "2":
            check_system_updates()
        elif security_choice == "3":
            while True:
                print("\nNetwork Security Checks:")
                print("1. Check for unauthorized devices on the network")
                print("2. Check for unauthorized access points")
                print("3. Check for rogue DHCP servers")
                print("4. Check for port security violations")
                print("5. Check for DNS spoofing")
                print("6. Check for SSL/TLS vulnerabilities")
                print("7. Back")
                
                network_security_choice = input("Enter your choice (1-7): ")
                
                if network_security_choice == "1":
                    check_unauthorized_devices()
                elif network_security_choice == "2":
                    check_unauthorized_access_points()
                elif network_security_choice == "3":
                    check_rogue_dhcp_servers()
                elif network_security_choice == "4":
                    check_port_security_violations()
                elif network_security_choice == "5":
                    check_dns_spoofing()
                elif network_security_choice == "6":
                    check_ssl_tls_vulnerabilities()
                elif network_security_choice == "7":
                    break
                else:
                    print("Invalid choice. Please try again.")
        elif security_choice == "4":
            check_system_logs()
        elif security_choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")
            
        elif choice == "8":
            exit
        else:
            print("Invalid choice. Please try again.")

# Call the menu function to start the program
menu()         
