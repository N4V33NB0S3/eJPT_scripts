import os
import threading
from queue import Queue
import time
import argparse
import ipaddress

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
    while not q.empty():
        try:
            # Get an IP address from the queue. 'block=False' prevents waiting.
            ip = q.get(block=False)
        except Queue.Empty:
            # If the queue is empty, the thread can exit.
            break

        # Construct the ping command.
        # '-c 1' sends one packet.
        # '-W {PING_TIMEOUT}' sets the timeout.
        # Redirection sends all output to /dev/null to keep the console clean.
        command = f"ping -c 1 -W {PING_TIMEOUT} {ip} > /dev/null 2>&1"
        response = os.system(command)

        # A response code of 0 means the ping was successful.
        if response == 0:
            print(f"[+] {ip} is up")
            with list_lock:
                active_hosts.append(ip)
        else:
            # Optional: uncomment the line below for verbose output on failed pings.
            # print(f"[-] {ip} is down")
            pass

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
        ip_queue.put(str(ip))

    # 2. Create and start the threads
    threads = []
    for _ in range(NUM_THREADS):
        # Create a thread that will run the pinger function.
        # 'daemon=True' allows the main program to exit even if threads are running.
        thread = threading.Thread(target=pinger, args=(ip_queue,), daemon=True)
        thread.start()
        threads.append(thread)

    # 3. Wait for the queue to be empty.
    # This means all IPs have been processed by the threads.
    ip_queue.join()

    # 4. Write the list of active hosts to the output file
    print("\n[INFO] Scan complete.")
    print(f"[INFO] Writing {len(active_hosts)} active hosts to {OUTPUT_FILE}...")
    
    # Sort the IPs for a clean and ordered output file.
    # We use the ip_address object for a correct numerical sort.
    sorted_hosts = sorted(active_hosts, key=ipaddress.ip_address)
    
    with open(OUTPUT_FILE, 'w') as f:
        for ip in sorted_hosts:
            f.write(f"{ip}\n")

    end_time = time.time()
    print(f"[INFO] Done. Scan took {end_time - start_time:.2f} seconds.")
    print("=" * 50)


if __name__ == '__main__':
    main()


