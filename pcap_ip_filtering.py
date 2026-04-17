#!/usr/bin/env python3

from scapy.all import rdpcap, wrpcap, IP

# ================= CONFIG =================
INPUT_PCAP = "/Users/nstda/Downloads/data/pcap/Python_on_off_airpurifier_capture_20260416_144649.pcap"
OUTPUT_PCAP = "filtered_output.pcap"

# List of allowed IPs (both src and dst)
FILTER_IPS = {
    "192.168.1.106",
    "224.0.23.0"
}
# ==========================================


def filter_pcap(input_file, output_file, ip_list):
    print(f"[INFO] Reading PCAP: {input_file}")
    packets = rdpcap(input_file)

    filtered_packets = []
    total = len(packets)
    kept = 0

    for pkt in packets:
        # Only process IP packets
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Filter condition:
            # Keep packet if BOTH src AND dst are in the list
            if src_ip in ip_list and dst_ip in ip_list:
                filtered_packets.append(pkt)
                kept += 1

    print(f"[INFO] Total packets: {total}")
    print(f"[INFO] Filtered packets: {kept}")

    print(f"[INFO] Writing output PCAP: {output_file}")
    wrpcap(output_file, filtered_packets)

    print("[DONE] Filtering complete.")


if __name__ == "__main__":
    filter_pcap(INPUT_PCAP, OUTPUT_PCAP, FILTER_IPS)