#!/usr/bin/env python3
from __future__ import annotations

import csv
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

# ============================================================
# Configuration
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
INPUT_DIR = (BASE_DIR / "/Users/nstda/PycharmProjects/pacp_feature_extraction/").resolve()          # original PCAPs
OUTPUT_CSV = BASE_DIR / "label_feature_IOT.csv"

DEVICE_IPS: Dict[str, List[str]] = {
    "TCP_Mobile": ["192.168.1.45"],
    "TCP_Outlet": ["192.168.1.222", "192.168.1.67"],
    "TCP_Assistant": [
        "192.168.1.111",
        "192.168.1.30",
        "192.168.1.42",
        "192.168.1.59",
        "192.168.1.70",
    ],
    "TCP_Camera": [
        "192.168.1.128",
        "192.168.1.145",
        "192.168.1.78",
    ],
    "TCP_Miscellaneous": [
        "192.168.1.216",
        "192.168.1.46",
        "192.168.1.84",
        "192.168.1.91",
    ],
}

FIELDS = [
    "ip.len",
    "ip.hdr_len",
    "ip.ttl",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size_value",
    "tcp.hdr_len",
    "tcp.len",
    "tcp.stream",
    "tcp.urgent_pointer",
    "ip.flags",
    "ip.id",
    "ip.checksum",
    "tcp.flags",
    "tcp.checksum",
]

CSV_HEADER = [
    "Label",
    "IPLength",
    "IPHeaderLength",
    "TTL",
    "Protocol",
    "SourcePort",
    "DestPort",
    "SequenceNumber",
    "AckNumber",
    "WindowSize",
    "TCPHeaderLength",
    "TCPLength",
    "TCPStream",
    "TCPUrgentPointer",
    "IPFlags",
    "IPID",
    "IPchecksum",
    "TCPflags",
    "TCPChecksum",
]


# ============================================================
# Helpers
# ============================================================

def ensure_tshark() -> str:
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        raise RuntimeError(
            "tshark was not found in PATH. Install Wireshark/tshark first."
        )
    return tshark_path


def build_display_filter(ips: List[str]) -> str:
    ip_expr = " || ".join(f'ip.src=={ip}' for ip in ips)
    return f"tcp && ({ip_expr})"


def run_tshark_extract(tshark: str, pcap_file: Path, display_filter: str) -> List[List[str]]:
    cmd = [
        tshark,
        "-r",
        str(pcap_file),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]

    for field in FIELDS:
        cmd.extend(["-e", field])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"tshark failed on {pcap_file.name}:\n{result.stderr.strip()}"
        )

    rows: List[List[str]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        # Since we forced comma output, split safely on commas.
        # Quote wrapping from tshark is acceptable for CSV writing.
        cols = [col.strip().strip('"') for col in line.split(",")]

        # Pad or trim just in case tshark returns uneven rows
        if len(cols) < len(FIELDS):
            cols.extend([""] * (len(FIELDS) - len(cols)))
        elif len(cols) > len(FIELDS):
            cols = cols[:len(FIELDS)]

        rows.append(cols)

    return rows


# ============================================================
# Main
# ============================================================

def main() -> None:
    tshark = ensure_tshark()

    pcap_files = sorted(INPUT_DIR.glob("*.pcap"))
    if not pcap_files:
        print(f"No PCAP files found in: {INPUT_DIR}")
        return

    total_rows = 0

    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)

        for pcap_file in pcap_files:
            print(f"Processing {pcap_file.name}...")

            for label, ips in DEVICE_IPS.items():
                display_filter = build_display_filter(ips)

                try:
                    rows = run_tshark_extract(tshark, pcap_file, display_filter)
                except RuntimeError as e:
                    print(f"[ERROR] {e}")
                    continue

                for row in rows:
                    writer.writerow([label] + row)

                total_rows += len(rows)
                print(f"  {label}: {len(rows)} rows")

    print(f"\nDone. Wrote {total_rows} rows to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()