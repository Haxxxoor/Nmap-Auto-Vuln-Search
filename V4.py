import subprocess
import re
import os

def sanitize_filename(filename):
    """
    Sanitizes the filename by removing special characters that are not allowed in filenames.
    """
    return re.sub(r'[\/:*?"<>|]', '_', filename)

def run_nmap_scan(target):
    """
    Runs an nmap scan on the target, writes the output to a text file based on the target name,
    and returns the output as a string.
    """
    print(f"Scanning {target} using nmap...")
    
    # Sanitize the target to use it as part of the filename
    output_file = sanitize_filename(f"{target}_nmap_scan.txt")
    
    nmap_command = ["nmap", "-sV", target]  # -sV detects service versions
    
    # Open the output file in write mode
    with open(output_file, 'w') as file:
        # Run the nmap scan and write the result to the file
        result = subprocess.run(nmap_command, stdout=subprocess.PIPE)
        file.write(result.stdout.decode())  # Write the nmap output to the file
    
    print(f"Nmap scan results saved to {output_file}")
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

def export_vulnerabilities(target, vulnerabilities):
    """
    Exports the vulnerabilities to a text file based on the target name.
    """
    output_file = sanitize_filename(f"{target}_vulnerabilities.txt")
    with open(output_file, 'w') as file:
        file.write(vulnerabilities)
    
    print(f"Vulnerabilities saved to {output_file}")

def main():
    target = input("Enter the target IP or domain: ")
    
    # Step 1: Run nmap scan and save output to a file
    nmap_output = run_nmap_scan(target)
    
    # Step 2: Parse nmap output to extract service names and versions
    services = parse_nmap_output(nmap_output)
    
    if not services:
        print("No services found in the nmap scan.")
        return
    
    # Step 3: Search for vulnerabilities using searchsploit and save to file
    all_vulnerabilities = ""
    for service, version in services:
        exploits = search_exploits(service, version)
        vulnerabilities_report = f"\nVulnerabilities for {service} {version}:\n{exploits}\n"
        print(vulnerabilities_report)
        all_vulnerabilities += vulnerabilities_report
    
    # Step 4: Export vulnerabilities to a file
    export_vulnerabilities(target, all_vulnerabilities)

if __name__ == "__main__":
    main()
