from scapy.all import ARP, Ether, srp
import subprocess
import time
import sqlite3
import logging
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socket

# Setup logging
logging.basicConfig(
    filename="network_monitor.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

DATABASE_NAME = "network_monitor.db"

# Database setup to store discovered IPs, Nmap results, and Searchsploit results
def setup_database():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS discovered_ips (
            ip TEXT UNIQUE,
            nmap_scan TEXT,
            searchsploit TEXT
        )
    """)
    conn.commit()
    conn.close()

# Check if the IP is already scanned
def is_ip_new(ip):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM discovered_ips WHERE ip=?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is None

# Add a new IP, Nmap result, and Searchsploit result to the database
def add_ip_to_database(ip, nmap_result, searchsploit_result):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO discovered_ips (ip, nmap_scan, searchsploit)
        VALUES (?, ?, ?)
    """, (ip, nmap_result, searchsploit_result))
    conn.commit()
    conn.close()

# Update the Nmap and Searchsploit results for an existing IP
def update_nmap_result(ip, nmap_result, searchsploit_result):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE discovered_ips
        SET nmap_scan=?, searchsploit=?
        WHERE ip=?
    """, (nmap_result, searchsploit_result, ip))
    conn.commit()
    conn.close()

# Function to scan the network
def scan_network(ip_range, interface):
    try:
        logging.info(f"Scanning the network: {ip_range} on interface {interface}")
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, iface=interface, timeout=2, verbose=False)[0]
        devices = []

        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        logging.info(f"Found {len(devices)} devices on the network.")
        return devices
    except Exception as e:
        logging.error(f"Error during network scan: {e}")
        return []

# Function to run Nmap vulnerability scan
def nmap_scan(ip):
    try:
        logging.info(f"Running nmap scan on {ip}...")
        result = subprocess.run(
            ["nmap", "-sV", "--script=vuln", ip], text=True, capture_output=True
        )
        logging.info(f"Nmap scan complete for {ip}.")

        # Parse services for Searchsploit
        services = []
        for line in result.stdout.splitlines():
            if "open" in line and "/" in line:  # Extract open services
                services.append(line)

        searchsploit_results = []
        for service in services:
            exploit_results = run_searchsploit(service)
            searchsploit_results.append(f"Service: {service}\n{exploit_results}")

        return result.stdout, "\n\n".join(searchsploit_results)
    except Exception as e:
        logging.error(f"Error running Nmap on {ip}: {e}")
        return "Error running Nmap.", "Error running Searchsploit."

# Function to run Searchsploit for identified services
def run_searchsploit(service_info):
    try:
        logging.info(f"Running Searchsploit for: {service_info}")
        result = subprocess.run(
            ["searchsploit", service_info], text=True, capture_output=True
        )
        logging.info(f"Searchsploit completed for: {service_info}")
        return result.stdout
    except Exception as e:
        logging.error(f"Error running Searchsploit for {service_info}: {e}")
        return "Error running Searchsploit."

# HTTP server handler
class DatabaseHandler(SimpleHTTPRequestHandler):
    def generate_html(self):
        # Generate a basic HTML page displaying the database content
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Monitor</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #121212;
                    color: #ffffff;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                    background-color: #1e1e1e;
                }
                th, td {
                    border: 1px solid #333;
                    padding: 8px;
                    text-align: left;
                    color: #ffffff;
                }
                th {
                    background-color: #333333;
                }
                pre {
                    background-color: #1e1e1e;
                    padding: 10px;
                    border: 1px solid #333;
                    color: #ffffff;
                    overflow-x: auto;
                }
            </style>
        </head>
        <body>
            <h1>Discovered IPs and Exploits</h1>
            <table>
                <tr><th>IP Address</th><th>Nmap Scan Results</th><th>Searchsploit Results</th></tr>
        """
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT ip, nmap_scan, searchsploit FROM discovered_ips")
        rows = cursor.fetchall()
        for row in rows:
            ip = row[0]
            nmap_scan = row[1] if row[1] else "No scan data available."
            searchsploit = row[2] if row[2] else "No exploit data available."
            html += f"<tr><td>{ip}</td><td><pre>{nmap_scan}</pre></td><td><pre>{searchsploit}</pre></td></tr>"
        conn.close()
        html += """
            </table>
        </body>
        </html>
        """
        return html

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self.generate_html().encode())
        else:
            self.send_error(404, "Page not found")

# Start the HTTP server
def start_http_server(port=8000):
    # Dynamically determine the server's IP address
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    logging.info(f"Starting HTTP server on IP {local_ip} and port {port}...")
    print(f"HTTP server is running on http://{local_ip}:{port}/")

    server_address = ('', port)
    httpd = HTTPServer(server_address, DatabaseHandler)
    logging.info("HTTP server is running...")
    httpd.serve_forever()

# Main loop
def main():
    setup_database()

    # Ask user for network details
    interface = input("Enter the network interface to use (e.g., wlan0, eth0): ")
    network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")

    logging.info("Starting network monitoring...")

    # Start the HTTP server in a separate thread
    import threading
    server_thread = threading.Thread(target=start_http_server, args=(8000,))
    server_thread.daemon = True
    server_thread.start()

    while True:
        try:
            devices = scan_network(network_range, interface)
            for device in devices:
                ip = device['ip']
                if is_ip_new(ip):
                    logging.info(f"New device detected: {ip}")
                    nmap_result, searchsploit_result = nmap_scan(ip)
                    add_ip_to_database(ip, nmap_result, searchsploit_result)
                else:
                    logging.info(f"Re-scanning known device: {ip}")
                    nmap_result, searchsploit_result = nmap_scan(ip)
                    update_nmap_result(ip, nmap_result, searchsploit_result)
        except Exception as e:
            logging.error(f"Unexpected error in main loop: {e}")

        time.sleep(30)  # Adjust as needed

if __name__ == "__main__":
    main()
