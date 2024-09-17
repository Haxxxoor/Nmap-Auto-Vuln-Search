import subprocess
import re

def run_nmap_scan(target):
    """
    Runs an nmap scan on the target and returns the output.
    """
    print(f"Scanning {target} using nmap...")
    nmap_command = ["nmap", "-sV", target]  # -sV detects service versions
    result = subprocess.run(nmap_command, stdout=subprocess.PIPE)
    return result.stdout.decode()

def parse_nmap_output(nmap_output):
    """
    Parses the nmap output to extract services and versions.
    Returns a list of tuples (service_name, version).
    """
    services = []
    # Regex pattern to match service details (Example: 80/tcp open http Apache httpd 2.4.29)
    service_pattern = re.compile(r"(\d+/\w+)\s+open\s+([\w-]+)\s+([\w\s\.-]+)")
    
    for line in nmap_output.split("\n"):
        match = service_pattern.search(line)
        if match:
            port = match.group(1)
            service_name = match.group(2)
            version = match.group(3).strip()
            services.append((service_name, version))
    
    return services

def search_exploits(service, version):
    """
    Uses searchsploit to find vulnerabilities based on the service name and version.
    """
    print(f"Searching for vulnerabilities in {service} {version}...")
    search_command = ["searchsploit", service, version]
    result = subprocess.run(search_command, stdout=subprocess.PIPE)
    return result.stdout.decode()

def main():
    target = input("Enter the target IP or domain: ")
    
    # Step 1: Run nmap scan
    nmap_output = run_nmap_scan(target)
    
    # Step 2: Parse nmap output to extract service names and versions
    services = parse_nmap_output(nmap_output)
    
    if not services:
        print("No services found in the nmap scan.")
        return
    
    # Step 3: Search for vulnerabilities using searchsploit
    for service, version in services:
        exploits = search_exploits(service, version)
        print(f"\nVulnerabilities for {service} {version}:\n{exploits}")

if __name__ == "__main__":
    main()
