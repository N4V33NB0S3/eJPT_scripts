import os
import threading
from queue import Queue
import time
import argparse
import ipaddress
import subprocess
import sys

# --- Configuration ---
# Number of concurrent threads to use for scanning.
# A higher number can be faster but uses more resources.
NUM_THREADS = 50
# The file where active hosts will be saved.
OUTPUT_FILE = "active_hosts.txt"
# Ping timeout in seconds.
PING_TIMEOUT = 1
# ---------------------

# A thread-safe queue to hold all the IP addresses to be scanned.
ip_queue = Queue()

# An event to signal all threads to stop.
stop_event = threading.Event()

# A thread-safe list to store the IP addresses that are up.
# We use a lock to ensure that appending to the list is safe across threads.
active_hosts = []
list_lock = threading.Lock()

def pinger(q):
    """
    Worker function that takes an IP from the queue, pings it,
    and adds it to the active_hosts list if it's responsive.
    This function is executed by each thread.
    """
    # The loop continues as long as there are items in the queue AND the stop event is not set.
    while not q.empty() and not stop_event.is_set():
        try:
            # Get an IP address from the queue. 'block=False' prevents waiting.
            ip = q.get(block=False)
        except Queue.Empty:
            # If the queue is empty, the thread can exit.
            break

        # Use subprocess for more control. This is for Linux.
        command = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), str(ip)]

        try:
            # We don't need the output, so we send it to DEVNULL.
            response = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=PING_TIMEOUT + 0.5)
            # A response code of 0 means the ping was successful.
            if response.returncode == 0:
                print(f"[+] {ip} is up")
                with list_lock:
                    active_hosts.append(str(ip))
        except subprocess.TimeoutExpired:
            # This handles cases where the ping command itself hangs
            pass
        except Exception:
            # Catch other potential exceptions
            pass
        finally:
            # Signal that the task from the queue is done.
            q.task_done()

def main():
    """
    Main function to set up threads, run the scan, and save the results.
    """
    parser = argparse.ArgumentParser(description="A fast, multi-threaded IP scanner.")
    parser.add_argument("subnet", help="The subnet to scan in CIDR notation (e.g., 192.168.1.0/24).")
    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.subnet, strict=False)
    except ValueError:
        print(f"[ERROR] Invalid subnet: {args.subnet}. Please use CIDR notation (e.g., 192.168.1.0/24).")
        return

    print("=" * 50)
    print(f"Scanning subnet: {network}")
    print(f"Using {NUM_THREADS} threads.")
    print("=" * 50)

    start_time = time.time()

    # 1. Populate the queue with all possible host IPs in the target subnet.
    for ip in network.hosts():
        ip_queue.put(ip)

    # 2. Create and start the threads
    threads = []
    for _ in range(NUM_THREADS):
        # We don't use daemon threads because we want to wait for them to finish.
        thread = threading.Thread(target=pinger, args=(ip_queue,))
        thread.start()
        threads.append(thread)

    try:
        # 3. Wait for the queue to be empty. This is the main blocking call.
        ip_queue.join()
    except KeyboardInterrupt:
        print("\n\n[!] User interrupted. Signalling threads to stop...")
        stop_event.set()

    # 4. Wait for all worker threads to complete their current task and exit.
    print("[INFO] Waiting for active threads to finish...")
    for thread in threads:
        thread.join()

    # 5. Write the list of active hosts to the output file
    print("\n[INFO] Scan finished or was interrupted.")
    if active_hosts:
        print(f"[INFO] Writing {len(active_hosts)} active hosts to {OUTPUT_FILE}...")
        
        # Sort the IPs for a clean and ordered output file.
        sorted_hosts = sorted(active_hosts, key=ipaddress.ip_address)
        
        with open(OUTPUT_FILE, 'w') as f:
            for ip in sorted_hosts:
                f.write(f"{ip}\n")
    else:
        print("[INFO] No active hosts were found.")


    end_time = time.time()
    print(f"[INFO] Done. Scan took {end_time - start_time:.2f} seconds.")
    print("=" * 50)


if __name__ == '__main__':
    main()


