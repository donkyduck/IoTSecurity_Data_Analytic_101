import os
from collections import defaultdict
from pathlib import Path

import numpy as np
from PIL import Image
from scapy.all import rdpcap, IP, TCP, UDP


TARGET_BYTES = 784          # 28 x 28
IMAGE_SIZE = 28
CNN_INPUT_SIZE = 32         # to match CNN table
PAD_VALUE = 0x00

BASE_DIR = Path(__file__).resolve().parent

# Input folder containing PCAP files
INPUT_DIR = Path("/Users/nstda/Documents/GitHub/IoTSecurity_Data_Analytic_101/pcap/").resolve()

# Output folder for generated images
OUTPUT_DIR = Path("/Users/nstda/Documents/GitHub/IoTSecurity_Data_Analytic_101/CNNimage/").resolve()


def get_session_key(pkt):
    """Return a bidirectional 5-tuple session key."""
    if IP not in pkt:
        return None

    proto = pkt[IP].proto
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        l4_proto = "TCP"
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        l4_proto = "UDP"
    else:
        src_port = 0
        dst_port = 0
        l4_proto = str(proto)

    a = (src_ip, src_port)
    b = (dst_ip, dst_port)

    if a <= b:
        return (a[0], a[1], b[0], b[1], l4_proto)
    return (b[0], b[1], a[0], a[1], l4_proto)


def extract_session_bytes(pkt):
    """Session + All: use the whole packet bytes."""
    return bytes(pkt)


def split_pcap_into_sessions(pcap_path):
    """Group packets into bidirectional sessions."""
    packets = rdpcap(str(pcap_path))
    sessions = defaultdict(bytearray)

    for pkt in packets:
        key = get_session_key(pkt)
        if key is None:
            continue

        pkt_bytes = extract_session_bytes(pkt)
        if len(pkt_bytes) == 0:
            continue

        sessions[key].extend(pkt_bytes)

    return sessions


def clean_sessions(session_dict):
    """Remove empty and duplicate sessions."""
    cleaned = {}
    seen = set()

    for key, data in session_dict.items():
        if len(data) == 0:
            continue

        data_bytes = bytes(data)
        if data_bytes in seen:
            continue

        seen.add(data_bytes)
        cleaned[key] = data_bytes

    return cleaned


def trim_or_pad(data_bytes, target_len=TARGET_BYTES, pad_value=PAD_VALUE):
    """Trim or zero-pad to fixed size."""
    if len(data_bytes) > target_len:
        return data_bytes[:target_len]
    if len(data_bytes) < target_len:
        return data_bytes + bytes([pad_value] * (target_len - len(data_bytes)))
    return data_bytes


def bytes_to_28x28_image(data_bytes):
    """Convert 784 bytes into a 28x28 grayscale image."""
    arr = np.frombuffer(data_bytes, dtype=np.uint8)
    return arr.reshape(28, 28)


def pad_28_to_32(img28):
    """Pad 28x28 image to 32x32."""
    img32 = np.zeros((32, 32), dtype=np.uint8)
    img32[2:30, 2:30] = img28
    return img32


def save_image(img_array, save_path):
    img = Image.fromarray(img_array, mode="L")
    img.save(save_path)


def process_pcap_to_images(pcap_path, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    sessions = split_pcap_into_sessions(pcap_path)
    sessions = clean_sessions(sessions)

    saved_files = []

    for idx, (key, data_bytes) in enumerate(sessions.items()):
        fixed = trim_or_pad(data_bytes, target_len=TARGET_BYTES)
        img28 = bytes_to_28x28_image(fixed)
        img32 = pad_28_to_32(img28)

        filename = f"session_{idx:05d}.png"
        save_path = output_dir / filename
        save_image(img32, save_path)

        saved_files.append((str(save_path), key))

    return saved_files


if __name__ == "__main__":
    print(f"Reading PCAPs from: {INPUT_DIR}")
    print(f"Saving images to:   {OUTPUT_DIR}")

    if not INPUT_DIR.exists():
        raise FileNotFoundError(f"Input directory not found: {INPUT_DIR}")

    pcap_files = list(INPUT_DIR.glob("*.pcap")) + list(INPUT_DIR.glob("*.pcapng"))

    if not pcap_files:
        raise FileNotFoundError(f"No .pcap or .pcapng files found in: {INPUT_DIR}")

    total_images = 0

    for pcap_file in pcap_files:
        print(f"\nProcessing: {pcap_file.name}")

        pcap_output_dir = OUTPUT_DIR / pcap_file.stem
        results = process_pcap_to_images(pcap_file, pcap_output_dir)

        print(f"Generated {len(results)} images for {pcap_file.name}")
        total_images += len(results)

    print(f"\nTotal generated images: {total_images}")