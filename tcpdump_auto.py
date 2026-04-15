#!/usr/bin/env python3

import subprocess
import datetime
import os
import signal
import sys

# ================= CONFIG =================
INTERFACE = "en9"
OUTPUT_DIR = os.path.expanduser("~/Downloads/data/pcap")
ROTATE_SECONDS = 300   # 5 minutes
SNAPLEN = 0            # full packet capture
# ==========================================


def ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"[INFO] Created directory: {OUTPUT_DIR}")


def generate_filename():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_pcap = f"Nmap_port_scan_capture_{timestamp}.pcap"
    return os.path.join(OUTPUT_DIR, filename_pcap)

def start_tcpdump():
    ensure_output_dir()

    filename = generate_filename()

    cmd = [
        "tcpdump",
        "-i", INTERFACE,
        "-s", str(SNAPLEN),
        "-nn",
        "-w", filename
    ]

    print("[INFO] Starting tcpdump...")
    print("[INFO] Interface:", INTERFACE)
    print("[INFO] Output file:", filename)
    print()

    return subprocess.Popen(cmd)


def signal_handler(sig, frame):
    print("\n[INFO] Stopping capture...")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)

    process = start_tcpdump()

    try:
        process.wait()
    except KeyboardInterrupt:
        print("\n[INFO] Terminated by user")
        process.terminate()


if __name__ == "__main__":
    main()