import os
import threading
from queue import Queue
import time
import argparse
import ipaddress
import subprocess
import sys
import platform
import logging
import socket
import json
import csv

# --- Configuration ---
MIN_THREADS = 8
MAX_THREADS = 100
DEFAULT_OUTPUT_FILE = "active_hosts"
PING_TIMEOUT = 1
# ---------------------

ip_queue = Queue()
stop_event = threading.Event()
active_hosts = []
list_lock = threading.Lock()
tasks_completed = 0
tasks_lock = threading.Lock()
print_lock = threading.Lock()

def get_ping_command(ip, timeout):
    """Returns the appropriate ping command based on the operating system."""
    if platform.system().lower() == "windows":
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(ip)]
    else:
        return ["ping", "-c", "1", "-W", str(timeout), str(ip)]

def check_port(ip, port, timeout=1):
    """Check if a specific port is open on the host."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((str(ip), port))
    sock.close()
    return result == 0

def pinger(q, args):
    """Worker function to ping IPs and optionally check multiple ports."""
    global tasks_completed
    while not q.empty() and not stop_event.is_set():
        try:
            ip = q.get(block=False)
        except Queue.Empty:
            break

        for attempt in range(args.retries):
            command = get_ping_command(ip, args.timeout)
            try:
                response = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=args.timeout + 0.5)
                if response.returncode == 0:
                    if args.ports:
                        open_ports = []
                        for port in args.ports:
                            if check_port(ip, port, args.timeout):
                                open_ports.append(str(port))
                                if args.verbose and not args.quiet:
                                    with print_lock:
                                        print(f"[+] {ip} is up and port {port} is open")
                            elif args.verbose and not args.quiet:
                                with print_lock:
                                    print(f"[+] {ip} is up but port {port} is closed")
                        if open_ports:
                            with list_lock:
                                active_hosts.append(f"{ip}:{','.join(open_ports)}")
                        elif not args.only_open_ports:
                            with list_lock:
                                active_hosts.append(str(ip))
                    else:
                        if args.verbose and not args.quiet:
                            with print_lock:
                                print(f"[+] {ip} is up")
                        with list_lock:
                            active_hosts.append(str(ip))
                    logging.info(f"Host {ip} is up")
                    break
                elif response.stderr and b"permission" in response.stderr.lower():
                    with print_lock:
                        print(f"[ERROR] Permission denied for ping. Try running with sudo.")
                    stop_event.set()
                    break
            except subprocess.TimeoutExpired:
                if attempt == args.retries - 1 and args.verbose and not args.quiet:
                    with print_lock:
                        print(f"[-] {ip} is down after {args.retries} attempts")
            except Exception as e:
                logging.error(f"Error pinging {ip}: {str(e)}")
            finally:
                with tasks_lock:
                    tasks_completed += 1
                q.task_done()

def progress_reporter(total_hosts, args):
    """Thread to report scanning progress based on tasks completed."""
    if args.quiet:
        return
    last_percentage = -1
    update_interval = max(1, total_hosts // 100)  # Update every 1% or at least once
    while not stop_event.is_set() and tasks_completed < total_hosts:
        with tasks_lock:
            completed = tasks_completed
        percentage = (completed / total_hosts) * 100
        # Only print if percentage has changed significantly (every 1% or so)
        if int(percentage * 10) > int(last_percentage * 10):
            with print_lock:
                print(f"Progress: {percentage:.1f}% ({completed}/{total_hosts} hosts)")
            last_percentage = percentage
        time.sleep(0.1)  # Update every 0.1 seconds
    # Final update to ensure 100% is shown
    with tasks_lock:
        completed = tasks_completed
    with print_lock:
        print(f"Progress: 100.0% ({completed}/{total_hosts} hosts)")

def setup_logging(quiet):
    """Set up logging to a file."""
    logging.basicConfig(
        filename="ip_scanner.log",
        level=logging.INFO if not quiet else logging.ERROR,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def get_output_filename(args):
    """Determine the output filename based on format and user input."""
    base_name = args.output_file if args.output_file else DEFAULT_OUTPUT_FILE
    if args.output_format == "json":
        return f"{base_name}.json"
    elif args.output_format == "csv":
        return f"{base_name}.csv"
    else:
        return f"{base_name}.txt"

def main():
    parser = argparse.ArgumentParser(description="A fast, multi-threaded IP scanner.")
    parser.add_argument("subnet", help="The subnet to scan in CIDR notation (e.g., 192.168.1.0/24).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Run in quiet mode.")
    parser.add_argument("-t", "--timeout", type=float, default=PING_TIMEOUT, help=f"Ping timeout in seconds (default: {PING_TIMEOUT}).")
    parser.add_argument("-r", "--retries", type=int, default=1, help="Number of ping attempts per host (default: 1).")
    parser.add_argument("-o", "--output-format", choices=["txt", "json", "csv"], default="txt", help="Output format: txt, json, or csv (default: txt).")
    parser.add_argument("-p", "--port", type=str, help="Optional: Comma-separated list of ports to check on active hosts (e.g., 80,443,22).")
    parser.add_argument("--only-open-ports", action="store_true", help="Only include hosts with at least one open port in the output.")
    parser.add_argument("--output-file", type=str, help="Custom output filename (without extension, default: active_hosts).")
    args = parser.parse_args()

    setup_logging(args.quiet)

    # Parse ports if provided
    args.ports = []
    if args.port:
        try:
            args.ports = [int(port) for port in args.port.split(",")]
            for port in args.ports:
                if not 1 <= port <= 65535:
                    raise ValueError(f"Invalid port: {port}")
        except ValueError as e:
            with print_lock:
                print(f"[ERROR] Invalid port list: {args.port}. Use comma-separated numbers (e.g., 80,443,22). {str(e)}")
            return

    try:
        network = ipaddress.ip_network(args.subnet, strict=False)
    except ValueError:
        with print_lock:
            print(f"[ERROR] Invalid subnet: {args.subnet}. Please use CIDR notation (e.g., 192.168.1.0/24).")
        return

    num_hosts = network.num_addresses - 2
    if num_hosts > 65534 and not args.quiet:
        with print_lock:
            print(f"[WARNING] Large subnet detected ({num_hosts} hosts). Consider reducing the range.")

    # Dynamic thread allocation
    cpu_count = os.cpu_count() or 4  # Fallback to 4 if cpu_count is None
    max_threads = min(max(MIN_THREADS, num_hosts // 100), cpu_count * 4, MAX_THREADS)
    output_file = get_output_filename(args)
    if not args.quiet:
        with print_lock:
            print("=" * 50)
            print(f"Scanning subnet: {network}")
            print(f"Using {max_threads} threads (based on {num_hosts} hosts and {cpu_count} CPU cores).")
            if args.ports:
                print(f"Checking ports: {', '.join(map(str, args.ports))}")
            print(f"Output will be saved to: {output_file}")
            print("=" * 50)
            print(f"Scanning {num_hosts} hosts...")

    start_time = time.time()

    # Populate queue
    for ip in network.hosts():
        ip_queue.put(ip)

    logging.info(f"Starting scan on {args.subnet} with {max_threads} threads")

    # Start progress reporter thread
    progress_thread = threading.Thread(target=progress_reporter, args=(num_hosts, args))
    progress_thread.start()

    # Create and start scanning threads
    threads = []
    for _ in range(max_threads):
        thread = threading.Thread(target=pinger, args=(ip_queue, args))
        thread.start()
        threads.append(thread)

    try:
        ip_queue.join()
    except KeyboardInterrupt:
        with print_lock:
            print("\n[!] User interrupted. Signalling threads to stop...")
        stop_event.set()

    with print_lock:
        print("[INFO] Waiting for active threads to finish...")
    for thread in threads:
        thread.join()
    progress_thread.join()

    # Write results
    if active_hosts and not args.quiet:
        with print_lock:
            print(f"[INFO] Writing {len(active_hosts)} active hosts to {output_file}...")

    sorted_hosts = sorted(active_hosts, key=lambda x: ipaddress.ip_address(x.split(':')[0]))
    if active_hosts:
        try:
            if args.output_format == "json":
                with open(output_file, 'w') as f:
                    json.dump({"active_hosts": sorted_hosts}, f, indent=4)
            elif args.output_format == "csv":
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["IP Address" + (":Ports" if args.ports else "")])
                    for ip in sorted_hosts:
                        writer.writerow([ip])
            else:
                with open(output_file, 'w') as f:
                    for ip in sorted_hosts:
                        f.write(f"{ip}\n")
        except PermissionError:
            with print_lock:
                print(f"[ERROR] Permission denied when writing to {output_file}. Try running with sudo or check file permissions.")
            return
        except Exception as e:
            with print_lock:
                print(f"[ERROR] Failed to write to {output_file}: {str(e)}")
            return
    elif not args.quiet:
        with print_lock:
            print("[INFO] No active hosts were found.")

    end_time = time.time()
    if not args.quiet:
        with print_lock:
            print(f"[INFO] Done. Scan took {end_time - start_time:.2f} seconds.")
            print("=" * 50)
    logging.info(f"Scan completed in {end_time - start_time:.2f} seconds")

if __name__ == '__main__':
    main()
