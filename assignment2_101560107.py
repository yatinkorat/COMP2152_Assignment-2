"""
Author: Yatin Korat
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print("Python Version: ", platform.python_version())
print("Operating System: ", os.name)

# Dictionary mapping port numbers to their common service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter lets us control how the target attribute
    # is accessed and modified, without exposing the private variable directly.
    # This is called encapsulation — it protects the data from being set to
    # invalid values. If we accessed self.__target directly, there would be no
    # way to validate or restrict what value gets assigned to it.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, which means it automatically gets
# the target property, the getter, the setter, and the destructor from the
# parent class without rewriting them. For example, when we call
# super().__init__(target), the parent constructor sets up self.__target,
# and we can use self.target in PortScanner as if we wrote it ourselves.

class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, if the program tries to scan a port on an unreachable
        # machine, Python would raise an unhandled exception and the entire program
        # would crash immediately. With try-except, we catch the socket.error gracefully,
        # print a helpful message, and continue scanning the remaining ports normally.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]
    

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously instead of
    # waiting for each one to finish before starting the next. Without threading,
    # scanning 1024 ports with a 1 second timeout each would take over 17 minutes.
    # With threads, all ports are scanned at roughly the same time, completing
    # in just a few seconds.
    

    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute("INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                           (target, result[0], result[1], result[2], str(datetime.datetime.now())))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        else:
            print("No past scans found.")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")

# ============================================================
# MAIN PROGRAM
# ============================================================
    
if __name__ == "__main__":
    # Get target IP
    target = input("Enter target IP address (press Enter for 127.0.0.1): ")
    if target == "":
        target = "127.0.0.1"

    # Get start port
    while True:
        try:
            start_port = int(input("Enter start port (1-1024): "))
            if start_port < 1 or start_port > 1024:
                print("Port must be between 1 and 1024.")
            else:
                break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Get end port
    while True:
        try:
            end_port = int(input("Enter end port (1-1024): "))
            if end_port < 1 or end_port > 1024:
                print("Port must be between 1 and 1024.")
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
            else:
                break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Create scanner and run
    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    # Print results
    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: Open ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    # Save to database
    save_results(target, scanner.scan_results)

    # Ask about history
    history = input("\nWould you like to see past scan history? (yes/no): ")
    if history.lower() == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# A useful feature would be a port export function that saves only the open ports
# to a .txt report file named with the target IP and scan date. It would use a
# list comprehension to filter open ports from scan_results, then write each one
# to the file in a readable format like "Port 22 (SSH) - Open".
# This makes it easy to share scan results without needing database access.
# Diagram: See diagram_101560107.png in the repository root